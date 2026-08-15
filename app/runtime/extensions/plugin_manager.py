import ast
import asyncio
import concurrent
import concurrent.futures
import importlib.util
import inspect
import os
import posixpath
import shutil
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union, Callable, Tuple

from fastapi import HTTPException
from starlette import status
from watchfiles import watch

from app import schemas
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.db.oper.systemconfig import SystemConfigOper
from app.foundation.crypto import RSAUtils
from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton
from app.foundation.version import compare_version
from app.adapters.system.host import SystemUtils
from app.adapters.external.market import PluginHelper, VERSION_BACKWARD_COMPATIBLE_FLAGS
from app.runtime.log import logger
from app.runtime.cache import fresh, async_fresh
from app.runtime.config import settings
from app.runtime.events import EventHandlerBinding, eventmanager
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_instance import instance_key, matches_plugin, plugin_id_of
from app.runtime.extensions.plugin_spi import (
    get_plugin_provided_modules,
    warn_legacy_module_injection,
)
from app.runtime.reload import ConfigReloadMixin
from app.schemas.types import EventType, SystemConfigKey

LegacyDiagnosticsConfigurator = Callable[..., None]
LegacyImportScanner = Callable[..., None]
PluginInstallReporter = Callable[..., None]
SiteAuthLevelProvider = Callable[[], int]


def _ignore_legacy_diagnostics(**_kwargs) -> None:
    """在启动组合根尚未注入兼容服务时保持插件加载可用。"""


def _unavailable_site_auth_level() -> int:
    """站点能力尚未装配时返回未认证等级。"""
    return 0


_legacy_diagnostics_configurator: LegacyDiagnosticsConfigurator = (
    _ignore_legacy_diagnostics
)
_legacy_import_scanner: LegacyImportScanner = _ignore_legacy_diagnostics
_plugin_install_reporter: PluginInstallReporter = _ignore_legacy_diagnostics
_site_auth_level_provider: SiteAuthLevelProvider = _unavailable_site_auth_level


def configure_plugin_legacy_import_services(
    *,
    diagnostics_configurator: LegacyDiagnosticsConfigurator,
    import_scanner: LegacyImportScanner,
) -> None:
    """由启动组合根注入插件旧导入诊断服务，避免扩展层反向依赖兼容层。"""
    global _legacy_diagnostics_configurator, _legacy_import_scanner
    _legacy_diagnostics_configurator = diagnostics_configurator
    _legacy_import_scanner = import_scanner


def configure_plugin_install_reporter(reporter: PluginInstallReporter) -> None:
    """由启动组合根注入插件安装上报器，避免扩展层依赖远程服务。"""
    global _plugin_install_reporter
    _plugin_install_reporter = reporter


def configure_site_auth_level_provider(provider: SiteAuthLevelProvider) -> None:
    """由启动组合根注入站点认证等级，避免扩展运行时依赖应用服务。"""
    global _site_auth_level_provider
    _site_auth_level_provider = provider


class PluginManager(ConfigReloadMixin, metaclass=Singleton):
    """插件管理器"""
    CONFIG_WATCH = {"DEV", "PLUGIN_AUTO_RELOAD", "PLUGIN_LOCAL_REPO_PATHS"}
    AGENT_TOOLS_BUILD_MAX_ATTEMPTS = 3

    def __init__(self):
        """初始化插件注册表、缓存和开发模式监控状态。"""
        # 插件列表，键为实例键，值为插件类；同一个类会被该插件的全部实例键指向
        self._plugins: dict = {}
        # 运行态插件列表，键为实例键，值为插件实例
        self._running_plugins: dict = {}
        # 监控线程
        self._monitor_thread: Optional[threading.Thread] = None
        # 监控停止事件
        self._stop_monitor_event = threading.Event()
        # 本地插件同步写入运行目录后的短时忽略窗口
        self._recent_local_sync: Dict[str, float] = {}
        # 插件智能体工具注册表缓存，插件启停或配置生效时主动失效。
        self._plugin_agent_tools_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._plugin_agent_tools_cache_lock = threading.Lock()
        self._plugin_agent_tools_revision: int = 0
        # 事件总线只通过通用解析器访问运行中的插件实例。
        eventmanager.register_handler_instance_resolver(
            "plugins",
            self.resolve_event_handler_instances,
        )
        # 开发者模式监测插件修改
        if settings.DEV or settings.PLUGIN_AUTO_RELOAD:
            self.__start_monitor()

    def resolve_event_handler_instances(
            self,
            owner_class: Type[Any],
    ) -> Optional[List[EventHandlerBinding]]:
        """
        为插件声明的事件方法解析当前全部运行实例

        同一个插件类可同时运行多个实例，事件需要投递给其中每一个。

        :param owner_class: 声明事件方法的插件类
        :return: 事件绑定列表，该插件未加载时返回 None
        """
        keys = self.get_instance_keys(owner_class.__name__)
        if not keys:
            return None
        bindings = []
        for key in keys:
            plugin = self._running_plugins.get(key)
            owner_name = key
            if plugin and callable(getattr(plugin, "get_name", None)):
                owner_name = plugin.get_name()
            bindings.append(EventHandlerBinding(
                instance=plugin,
                owner_name=owner_name,
                run_sync_in_threadpool=True,
                instance_key=key,
            ))
        return bindings

    def get_instance_keys(self, plugin_id: str) -> List[str]:
        """
        获取插件当前已登记的全部实例键

        :param plugin_id: 插件ID
        :return: 实例键列表，插件未加载时为空
        """
        keys = []
        for key in {**self._plugins, **self._running_plugins}:
            if plugin_id_of(key) == plugin_id and key not in keys:
                keys.append(key)
        return keys

    def has_plugin(self, plugin_id: str) -> bool:
        """
        判断插件是否已加载

        :param plugin_id: 插件ID
        :return: 是否存在该插件的任一实例
        """
        return bool(self.get_instance_keys(plugin_id))

    def _get_plugin_class(self, plugin_id: str) -> Optional[Type[Any]]:
        """
        按插件ID取插件类

        :param plugin_id: 插件ID
        :return: 插件类，未加载时为 None
        """
        plugin_class = self._plugins.get(plugin_id)
        if plugin_class is not None:
            return plugin_class
        for key, candidate in self._plugins.items():
            if plugin_id_of(key) == plugin_id:
                return candidate
        return None

    def _resolve_running_plugin(self, key: str) -> Optional[Any]:
        """
        按实例键取运行实例，传入插件ID时回落到该插件的首个实例

        :param key: 实例键或插件ID
        :return: 插件实例，未运行时为 None
        """
        plugin = self._running_plugins.get(key)
        if plugin is not None:
            return plugin
        for running_key, running in self._running_plugins.items():
            if plugin_id_of(running_key) == key:
                return running
        return None

    @staticmethod
    def _distinct_plugin_ids(container: Dict[str, Any]) -> List[str]:
        """
        按登记顺序去重取插件ID

        :param container: 以实例键为键的插件容器
        :return: 插件ID列表
        """
        return list(dict.fromkeys(plugin_id_of(key) for key in container))

    @staticmethod
    def _list_instance_ids(plugin_id: str) -> List[str]:
        """
        列出插件需要拉起的实例标识

        一个实例都没有配置时按默认实例拉起，使未创建分身的插件行为保持不变。

        :param plugin_id: 插件ID
        :return: 实例标识列表
        """
        try:
            records = PluginConfigOper().list_instances(plugin_id) or []
        except Exception as err:
            logger.error(f"读取插件 {plugin_id} 实例列表出错：{str(err)}")
            records = []
        instance_ids = []
        for record in records:
            if not record.instance_id:
                continue
            try:
                normalized = normalize_instance_id(record.instance_id)
            except ValueError as err:
                logger.error(f"跳过插件 {plugin_id} 的非法实例配置：{str(err)}")
                continue
            if normalized not in instance_ids:
                instance_ids.append(normalized)
        return instance_ids or [DEFAULT_INSTANCE_ID]

    @staticmethod
    def _instantiate_plugin(plugin_class: Type[Any], plugin_id: str, instance_id: str) -> Any:
        """
        构造插件实例并写入运行时身份

        插件普遍自带无参 ``__init__``，直接传身份参数会抛 TypeError，因此先按签名探测，
        只把 ``__init__`` 显式接受的身份参数传进去；构造完成后统一写入身份，
        两条路径得到的 plugin_id / instance_id 一致。

        :param plugin_class: 插件类
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 插件实例
        """
        try:
            parameters = inspect.signature(plugin_class.__init__).parameters
        except (TypeError, ValueError):
            parameters = {}
        accepted = (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        kwargs = {
            name: value
            for name, value in (("plugin_id", plugin_id), ("instance_id", instance_id))
            if name in parameters and parameters[name].kind in accepted
        }
        plugin_obj = plugin_class(**kwargs)
        # 身份由框架掌握：无参构造的插件在这里补齐，带参构造的插件在这里对齐
        plugin_obj._plugin_id = plugin_id  # noqa: SLF001
        plugin_obj._instance_id = normalize_instance_id(instance_id)  # noqa: SLF001
        return plugin_obj

    def init_config(self):
        """按最新系统配置完整重启插件。"""
        # 停止已有插件
        self.stop()
        # 启动插件
        self.start()

    def start(self, pid: Optional[str] = None):
        """
        启动加载插件
        :param pid: 插件ID，为空加载所有插件
        """

        _legacy_diagnostics_configurator(
            enabled=settings.DEBUG,
            emitter=logger.warning,
        )

        def check_module(module: Any):
            """
            检查模块
            """
            if not hasattr(module, 'init_plugin') or not hasattr(module, "plugin_name"):
                return False
            return True

        # 已安装插件
        installed_plugins = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 扫描插件目录，只加载符合条件的插件
        plugins = self._load_selective_plugins(pid, installed_plugins, check_module)
        # 排序
        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        for plugin in plugins:
            plugin_id = plugin.__name__
            if pid and plugin_id != pid:
                continue
            # 判断插件是否满足认证要求，如不满足则不进行实例化
            if not self.__set_and_check_auth_level(plugin=plugin):
                # 如果是插件热更新实例，这里则进行替换
                for key in self.get_instance_keys(plugin_id):
                    self._plugins[key] = plugin
                continue
            # 逐个拉起该插件已配置的实例
            for instance_id in self._list_instance_ids(plugin_id):
                key = instance_key(plugin_id, instance_id)
                try:
                    # 存储Class
                    self._plugins[key] = plugin
                    # 生成实例
                    plugin_obj = self._instantiate_plugin(plugin, plugin_id, instance_id)
                    # 生效插件配置
                    plugin_obj.init_plugin(self.get_plugin_config(plugin_id, instance_id))
                    # 存储运行实例
                    self._running_plugins[key] = plugin_obj
                    logger.info(f"加载插件：{key} 版本：{plugin_obj.plugin_version}")
                    # 启用的插件实例才设置事件注册状态可用
                    if plugin_obj.get_state():
                        eventmanager.enable_event_handler(plugin, key)
                    else:
                        eventmanager.disable_event_handler(plugin, key)
                except Exception as err:
                    logger.error(f"加载插件 {key} 出错：{str(err)} - {traceback.format_exc()}")
        self._register_plugin_modules(pid)
        self.clear_plugin_agent_tools_cache()

    def init_plugin(self, plugin_id: str, conf: dict, instance_id: str = DEFAULT_INSTANCE_ID):
        """
        初始化插件
        :param plugin_id: 插件ID
        :param conf: 插件配置
        :param instance_id: 实例ID
        """
        key = instance_key(plugin_id, instance_id)
        plugin = self._running_plugins.get(key)
        if not plugin:
            return
        # 初始化插件
        plugin.init_plugin(conf)
        # 为声明了 provides_models 的插件建立其自管理的表，失败不影响插件其它功能
        try:
            from app.db.plugin import setup_plugin_database
            setup_plugin_database(plugin)
        except Exception as err:
            logger.error(f"初始化插件 {plugin_id} 自管理数据库出错：{str(err)}")
        # 插件启停和配置变更都可能改变模块声明，先回收再按最新声明注册；
        # 排在自管理表建立之后，使模块初始化能用上插件自己的表
        self._unregister_module_owners([key])
        self._register_plugin_modules(key)
        # 检查插件实例状态并启用/禁用事件处理器
        if plugin.get_state():
            # 启用该实例的事件处理器
            eventmanager.enable_event_handler(type(plugin), key)
        else:
            # 禁用该实例的事件处理器
            eventmanager.disable_event_handler(type(plugin), key)
        self.clear_plugin_agent_tools_cache()

    def clear_plugin_agent_tools_cache(self) -> None:
        """
        清空插件智能体工具注册表缓存。
        """
        with self._plugin_agent_tools_cache_lock:
            self._plugin_agent_tools_cache.clear()
            self._plugin_agent_tools_revision += 1

    def get_plugin_agent_tools_revision(self) -> int:
        """
        获取插件智能体工具注册表版本号。
        """
        with self._plugin_agent_tools_cache_lock:
            return self._plugin_agent_tools_revision

    def stop(self, pid: Optional[str] = None, instance_id: Optional[str] = None):
        """
        停止插件服务
        :param pid: 插件ID，为空停止所有插件
        :param instance_id: 实例ID，为空停止该插件的全部实例
        """
        if pid and instance_id:
            targets = [instance_key(pid, instance_id)]
        elif pid:
            # 插件加载失败时不会进入任何容器，仍按默认实例键回收其可能残留的注册
            targets = self.get_instance_keys(pid) or [instance_key(pid)]
        else:
            targets = None
        # 回收插件注册的系统模块，插件未进入运行态时同样按来源清理，避免残留
        if targets is None:
            self._unregister_plugin_modules()
        else:
            self._unregister_module_owners(targets)
        # 停止插件
        if targets is not None:
            logger.info(f"正在停止插件 {pid}...")
            plugins = {key: self._running_plugins[key] for key in targets
                       if key in self._running_plugins}
            if not plugins:
                # 指定插件可能在上次加载时已导入模块但初始化失败，此时不会进入运行态列表。
                # 仍需继续清理类缓存和 sys.modules，避免后续热重载反复复用旧模块。
                logger.debug(f"插件 {pid} 不存在或未加载")
        else:
            logger.info("正在停止所有插件...")
            plugins = self._running_plugins
        for key, plugin in plugins.items():
            eventmanager.disable_event_handler(type(plugin), key)
            self.__stop_plugin(plugin)
        # 清空对象
        if targets is not None:
            # 清空指定实例
            for key in targets:
                self._plugins.pop(key, None)
                self._running_plugins.pop(key, None)
            # 同插件还有实例在运行时保留模块缓存，避免运行中的实例与重新导入的类对象脱节
            if not self.has_plugin(pid):
                # 清除插件模块缓存，包括所有子模块
                self._clear_plugin_modules(pid)
        else:
            # 清空
            self._plugins = {}
            self._running_plugins = {}
            # 清除所有插件模块缓存
            self._clear_plugin_modules()
        self.clear_plugin_agent_tools_cache()
        logger.info("插件停止完成")

    def _register_plugin_modules(self, pid: Optional[str] = None) -> None:
        """
        把插件经 provides_modules() 声明的系统模块注册进模块管理器

        无插件声明模块时不触碰模块管理器，避免提前触发模块全量装载。

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        provided = get_plugin_provided_modules(self._running_plugins, pid)
        if not provided:
            return
        module_manager = ModuleManager()
        for key, modules in provided.items():
            for module in modules:
                module_manager.register_module(module, owner=key)

    def _unregister_plugin_modules(self, pid: Optional[str] = None) -> None:
        """
        回收插件注册的系统模块

        :param pid: 插件ID，为空时回收全部已加载实例
        """
        if pid:
            owners = self.get_instance_keys(pid) or [instance_key(pid)]
        else:
            owners = list({**self._plugins, **self._running_plugins})
        self._unregister_module_owners(owners)

    @staticmethod
    def _unregister_module_owners(owners: List[str]) -> None:
        """
        按注册来源回收系统模块

        :param owners: 注册来源的实例键列表
        """
        module_manager = ModuleManager.get_existing_instance()
        if module_manager is None:
            return
        for owner in owners:
            removed = module_manager.unregister_modules(owner)
            if removed:
                logger.info(f"已回收插件 {owner} 注册的模块：{'、'.join(removed)}")

    @staticmethod
    def _load_selective_plugins(pid: Optional[str], installed_plugins: List[str],
                                check_module_func: Callable) -> List[Any]:
        """
        选择性加载插件，只import符合条件的插件
        :param pid: 指定插件ID，为空则加载所有已安装插件
        :param installed_plugins: 已安装插件列表
        :param check_module_func: 模块检查函数
        :return: 插件类列表
        """
        import importlib

        plugins = []
        plugins_dir = settings.ROOT_PATH / "app" / "plugins"

        if not plugins_dir.exists():
            logger.warning(f"插件目录不存在：{plugins_dir}")
            return plugins

        # 确定需要加载的插件目录名称列表
        if pid:
            # 加载指定插件
            target_plugins = [pid.lower()]
        else:
            # 加载已安装插件
            target_plugins = [plugin_id.lower() for plugin_id in installed_plugins]

        if not target_plugins:
            logger.debug("没有需要加载的插件")
            return plugins

        # 扫描plugins目录
        _loaded_modules = set()
        for plugin_dir in plugins_dir.iterdir():
            if not plugin_dir.is_dir() or plugin_dir.name.startswith('_'):
                continue

            # 检查是否是需要加载的插件
            if plugin_dir.name not in target_plugins:
                logger.debug(f"跳过插件目录：{plugin_dir.name}（不在加载列表中）")
                continue

            # 检查__init__.py是否存在
            init_file = plugin_dir / "__init__.py"
            if not init_file.exists():
                logger.debug(f"跳过插件目录：{plugin_dir.name}（缺少__init__.py）")
                continue

            try:
                # 构建模块名
                module_name = f"app.plugins.{plugin_dir.name}"
                logger.debug(f"正在导入插件模块：{module_name}")

                _legacy_import_scanner(
                    plugin_id=plugin_dir.name,
                    plugin_dir=plugin_dir,
                )

                # 导入模块
                module = importlib.import_module(module_name)

                # 检查模块中的类
                for name, obj in module.__dict__.items():
                    if name.startswith('_') or not isinstance(obj, type):
                        continue
                    if name in _loaded_modules:
                        continue
                    if check_module_func(obj):
                        _loaded_modules.add(name)
                        plugins.append(obj)
                        logger.debug(f"找到符合条件的插件类：{name}")
                        break

            except Exception as err:
                logger.error(f"加载插件 {plugin_dir.name} 失败：{str(err)} - {traceback.format_exc()}")

        return plugins

    @property
    def running_plugins(self) -> Dict[str, Any]:
        """
        获取运行态插件列表
        :return: 运行态插件列表
        """
        return self._running_plugins

    @property
    def plugins(self) -> Dict[str, Any]:
        """
        获取插件列表
        :return: 插件列表
        """
        return self._plugins

    def on_config_changed(self):
        """在插件监控配置变化后重建文件监控。"""
        self.reload_monitor()

    def get_reload_name(self) -> str:
        """返回配置重载日志使用的功能名称。"""
        return "插件文件修改监测"

    def reload_monitor(self):
        """
        重新加载插件文件修改监测
        """
        if settings.DEV or settings.PLUGIN_AUTO_RELOAD:
            # 先关闭已有监测，再重新启动
            self.stop_monitor()
            self.__start_monitor()
        else:
            self.stop_monitor()

    def __start_monitor(self):
        """
        启用监测插件文件修改监测
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.info("插件文件修改监测已经在运行中...")
            return

        logger.info("开始监测插件文件修改...")

        # 在启动新线程之前，确保停止事件是清除状态
        self._stop_monitor_event.clear()

        # 创建并启动监控线程
        self._monitor_thread = threading.Thread(
            target=self._run_file_watcher,
            daemon=True
        )
        self._monitor_thread.start()

    def stop_monitor(self):
        """
        停止监测插件文件修改监测
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.info("正在停止插件文件修改监测...")
            self._stop_monitor_event.set()
            self._monitor_thread.join(timeout=5)
            if self._monitor_thread.is_alive():
                logger.warning("插件文件修改监测线程在5秒内未能正常停止。")
            self._monitor_thread = None
            logger.info("插件文件修改监测停止完成")
        else:
            logger.info("未启用插件文件修改监测，无需停止")

    def _run_file_watcher(self):
        """
        运行 watchfiles 监视器的主循环。
        """
        # 监视插件目录
        plugin_paths = [str(settings.ROOT_PATH / "app" / "plugins")]
        for local_repo_path in PluginHelper.get_local_repo_paths():
            if local_repo_path.exists() and local_repo_path.is_dir():
                plugin_paths.append(str(local_repo_path))
        logger.info(">>> 监控线程已启动，准备进入watch循环...")
        # 使用 watchfiles 监视目录变化，并响应变化事件
        # Todo: yield_on_timeout = True 时，每秒检查停止事件，会返回空集合；后续可以考虑用来做心跳之类的功能？
        for changes in watch(*plugin_paths, stop_event=self._stop_monitor_event, rust_timeout=1000,
                             yield_on_timeout=True):
            # 如果收到停止事件，退出循环
            if not changes:
                continue

            # 处理变化事件
            plugins_to_reload = set()
            local_plugins_to_sync = {}
            for _change_type, path_str in changes:
                event_path = Path(path_str)

                # 跳过 pycache 目录中的文件
                if "__pycache__" in event_path.parts:
                    continue

                if event_path.name == "requirements.txt":
                    candidate = self._get_local_plugin_candidate_from_path(event_path)
                    if candidate:
                        if candidate.get("compatible") is False:
                            logger.info(
                                f"检测到本地插件 {candidate.get('id')} 依赖文件变化，"
                                f"但跳过处理：{candidate.get('skip_reason')}"
                            )
                            continue
                        logger.warn(f"检测到本地插件 {candidate.get('id')} 依赖文件变化，请重新安装本地插件以安装依赖")
                    continue

                federated_change = self._get_federated_plugin_change(event_path)
                if federated_change:
                    pid, candidate, remote_entry_ready = federated_change
                    # 运行目录由构建方直接写入；外部本地仓库只在入口完整时同步运行副本。
                    if candidate and remote_entry_ready:
                        if candidate.get("compatible") is False:
                            logger.info(
                                f"检测到本地插件 {pid} 联邦构建产物变化，"
                                f"但跳过同步：{candidate.get('skip_reason')}"
                            )
                        elif pid not in local_plugins_to_sync:
                            local_plugins_to_sync[pid] = (candidate, event_path, False)
                    continue

                # 跳过非 .py 文件
                if not event_path.name.endswith(".py"):
                    continue

                # 解析插件ID
                runtime_pid = self._get_plugin_id_from_path(event_path)
                local_candidate = self._get_local_plugin_candidate_from_path(event_path) if not runtime_pid else None
                if runtime_pid:
                    last_sync_time = self._recent_local_sync.get(runtime_pid)
                    if last_sync_time and time.time() - last_sync_time < 2:
                        continue
                    # 运行目录变化只重载，不能反向触发本地同步。
                    plugins_to_reload.add(runtime_pid)
                elif local_candidate:
                    if local_candidate.get("compatible") is False:
                        package_version = local_candidate.get("package_version")
                        source_root = f"plugins.{package_version}" if package_version else "plugins"
                        logger.info(
                            f"检测到本地插件 {local_candidate.get('id')} 文件变化，来源：{source_root}，"
                            f"文件：{event_path}，但跳过同步：{local_candidate.get('skip_reason')}"
                        )
                        continue
                    local_plugins_to_sync[local_candidate.get("id")] = (local_candidate, event_path, True)

            for pid, (candidate, event_path, should_reload) in local_plugins_to_sync.items():
                package_version = candidate.get("package_version")
                source_root = f"plugins.{package_version}" if package_version else "plugins"
                change_name = "Python 文件" if should_reload else "联邦构建产物"
                logger.info(f"检测到本地插件 {pid} {change_name}变化，来源：{source_root}，文件：{event_path}")
                if self._sync_local_plugin_if_installed(pid, candidate) and should_reload:
                    plugins_to_reload.add(pid)

            # 触发重载
            if plugins_to_reload:
                logger.info(f"检测到插件文件变化，准备重载: {list(plugins_to_reload)}")
                for pid in plugins_to_reload:
                    try:
                        self.reload_plugin(pid)
                    except Exception as e:
                        logger.error(f"插件 {pid} 热重载失败: {e}", exc_info=True)

    def _get_federated_plugin_change(
        self,
        event_path: Path,
    ) -> Optional[Tuple[str, Optional[dict], bool]]:
        """
        识别运行态 Vue 插件声明目录内的构建产物变化。

        :return: 插件 ID、本地仓库候选和联邦入口是否完整；非联邦目录变化返回 None。
        """
        try:
            event_path = event_path.resolve()
            candidate = self._get_local_plugin_candidate_from_path(event_path)
            if candidate:
                pid = candidate.get("id")
                plugin_dir = Path(candidate.get("path")).resolve()
            else:
                runtime_root = (settings.ROOT_PATH / "app" / "plugins").resolve()
                if not event_path.is_relative_to(runtime_root):
                    return None
                relative_parts = event_path.relative_to(runtime_root).parts
                if not relative_parts:
                    return None
                plugin_dir = runtime_root / relative_parts[0]
                pid = next(
                    (
                        plugin_id_of(key)
                        for key in self._running_plugins
                        if plugin_id_of(key).lower() == relative_parts[0].lower()
                    ),
                    None,
                )

            if not pid:
                return None
            plugin = self._resolve_running_plugin(pid)
            if not plugin:
                return None

            render_mode, dist_path = plugin.get_render_mode()
            if render_mode != "vue" or not isinstance(dist_path, str) or not dist_path:
                return None

            relative_dist_path = Path(dist_path)
            if relative_dist_path.is_absolute() or ".." in relative_dist_path.parts or "\\" in dist_path:
                return None

            plugin_dir = plugin_dir.resolve()
            dist_dir = (plugin_dir / relative_dist_path).resolve()
            if (
                dist_dir == plugin_dir
                or not dist_dir.is_relative_to(plugin_dir)
                or not event_path.is_relative_to(dist_dir)
            ):
                return None

            remote_entry = dist_dir / "remoteEntry.js"
            remote_entry_ready = (
                remote_entry.is_file()
                and remote_entry.resolve().is_relative_to(plugin_dir)
            )
            return pid, candidate, remote_entry_ready
        except Exception as e:
            logger.error(f"识别插件联邦构建产物变化时出错: {e}")
            return None

    @staticmethod
    def _get_plugin_id_from_path(event_path: Path) -> Optional[str]:
        """
        根据文件路径解析出插件的ID。
        :param event_path: 被修改文件的 Path 对象。
        :return: 插件ID字符串，如果不是有效插件文件则返回 None。
        """
        try:
            event_path = event_path.resolve()
            plugins_root = settings.ROOT_PATH / "app" / "plugins"
            # 确保修改的文件在 plugins 目录下
            if not event_path.is_relative_to(plugins_root):
                return None

            try:
                plugin_dir_name = event_path.relative_to(plugins_root).parts[0]
                plugin_dir = plugins_root / plugin_dir_name
            except (ValueError, IndexError):
                return None

            init_file = plugin_dir / "__init__.py"
            if not init_file.exists():
                return None

            # 读取 __init__.py 文件，查找插件主类名
            with open(init_file, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            tree = ast.parse(source_code)

            # 遍历AST，查找继承自 _PluginBase 的类
            for node in ast.walk(tree):
                # 检查节点是否为类定义
                if isinstance(node, ast.ClassDef):
                    # 遍历该类的所有基类
                    for base in node.bases:
                        # 检查基类是否是我们寻找的 _PluginBase
                        # ast.Name 用于处理简单的基类名
                        if isinstance(base, ast.Name) and base.id == '_PluginBase':
                            # 返回这个类的名字
                            return node.name

            return None
        except Exception as e:
            logger.error(f"从路径解析插件ID时出错: {e}")
            return None

    @staticmethod
    def _get_local_plugin_candidate_from_path(event_path: Path) -> Optional[dict]:
        """
        根据本地插件仓库路径解析具体插件候选，保留 plugins/plugins.v2 来源差异
        """
        try:
            event_path = event_path.resolve()
            for local_repo_path in PluginHelper.get_local_repo_paths():
                if not local_repo_path.exists() or not local_repo_path.is_dir():
                    continue
                if not event_path.is_relative_to(local_repo_path):
                    continue
                try:
                    relative_parts = event_path.relative_to(local_repo_path).parts
                except (ValueError, IndexError):
                    continue
                if len(relative_parts) < 2:
                    continue
                if relative_parts[0] == "plugins":
                    package_version = ""
                elif relative_parts[0].startswith("plugins."):
                    package_version = relative_parts[0].split(".", 1)[1]
                else:
                    continue
                plugin_dir_name = relative_parts[1]
                candidate = PluginHelper().get_local_plugin_candidate(
                    pid=plugin_dir_name,
                    package_version=package_version,
                    repo_path=local_repo_path,
                    strict_compat=False,
                    strict_system_version=not settings.DEV
                )
                if candidate:
                    return candidate
            return None
        except Exception as e:
            logger.error(f"从本地插件仓库路径解析插件候选时出错: {e}")
            return None

    @staticmethod
    def _sync_local_plugin_if_installed(pid: str, candidate: Optional[dict] = None) -> bool:
        """
        已安装本地插件源码变化时，同步到运行目录
        """
        installed_plugins = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        if pid not in installed_plugins:
            logger.info(f"本地插件 {pid} 尚未安装，跳过自动同步和热重载")
            return False

        candidate = candidate or PluginHelper().get_local_plugin_candidate(pid)
        if not candidate:
            return False
        if candidate.get("compatible") is False:
            logger.info(f"本地插件 {pid} 不满足同步条件，跳过自动同步：{candidate.get('skip_reason')}")
            return False

        source_dir = Path(candidate.get("path"))
        dest_dir = settings.ROOT_PATH / "app" / "plugins" / pid.lower()
        try:
            if source_dir.resolve() == dest_dir.resolve():
                return True
            if dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)
            shutil.copytree(
                source_dir,
                dest_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", "node_modules")
            )
            PluginManager()._recent_local_sync[pid] = time.time()
            logger.info(f"已同步本地插件 {pid}：{source_dir} -> {dest_dir}")
            return True
        except Exception as e:
            logger.error(f"同步本地插件 {pid} 失败：{e}")
            return False

    @staticmethod
    def __stop_plugin(plugin: Any):
        """
        停止插件
        :param plugin: 插件实例
        """
        try:
            # 关闭数据库
            if hasattr(plugin, "close"):
                plugin.close()
            # 关闭插件
            if hasattr(plugin, "stop_service"):
                plugin.stop_service()
        except Exception as e:
            logger.warn(f"停止插件 {plugin.get_name()} 时发生错误: {str(e)}")

    def remove_plugin(self, plugin_id: str, instance_id: Optional[str] = None):
        """
        从内存中移除一个插件
        :param plugin_id: 插件ID
        :param instance_id: 实例ID，为空时移除该插件的全部实例
        """
        self.stop(plugin_id, instance_id)
        self._dispose_plugin_database(plugin_id)

    def _dispose_plugin_database(self, plugin_id: str) -> None:
        """
        插件最后一个实例下线后释放其自管理数据库连接

        同一插件的多个实例共享一个库，仍有实例在运行时释放会掐断其余实例的连接。

        :param plugin_id: 插件ID
        """
        if self.has_plugin(plugin_id):
            return
        # 只释放连接、保留数据：删库只在明确删除插件数据时进行
        try:
            from app.db.plugin import db_manager
            db_manager.dispose(plugin_id)
        except Exception as err:
            logger.error(f"释放插件 {plugin_id} 自管理数据库连接出错：{str(err)}")

    def reload_plugin(self, plugin_id: str):
        """
        将一个插件重新加载到内存
        :param plugin_id: 插件ID
        """
        # 先移除插件实例
        self.stop(plugin_id)
        # 重新加载
        self.start(plugin_id)
        # 广播事件
        eventmanager.send_event(EventType.PluginReload, data={"plugin_id": plugin_id})

    @staticmethod
    def _clear_plugin_modules(plugin_id: Optional[str] = None):
        """
        清除插件及其所有子模块的缓存
        :param plugin_id: 插件ID
        """

        # 构建插件模块前缀
        if plugin_id:
            plugin_module_prefix = f"app.plugins.{plugin_id.lower()}"
        else:
            plugin_module_prefix = "app.plugins"

        # 收集需要删除的模块名（创建模块名列表的副本以避免迭代时修改字典）
        modules_to_remove = []
        for module_name in list(sys.modules.keys()):
            if module_name == plugin_module_prefix or module_name.startswith(plugin_module_prefix + "."):
                modules_to_remove.append(module_name)

        # 删除模块
        for module_name in modules_to_remove:
            try:
                del sys.modules[module_name]
                logger.debug(f"已清除插件模块缓存：{module_name}")
            except KeyError:
                # 模块可能已经被删除
                pass

        importlib.invalidate_caches()
        logger.debug("已清除查找器的缓存")

        if plugin_id:
            if modules_to_remove:
                logger.info(f"插件 {plugin_id} 共清除 {len(modules_to_remove)} 个模块缓存：{modules_to_remove}")
            else:
                logger.debug(f"插件 {plugin_id} 没有找到需要清除的模块缓存")

    def sync(self) -> List[str]:
        """
        安装本地不存在或需要更新的插件
        """

        def install_plugin(plugin):
            start_time = time.time()
            state, msg = PluginHelper().install(pid=plugin.id, repo_url=plugin.repo_url, force_install=True)
            elapsed_time = time.time() - start_time
            if state:
                _plugin_install_reporter(
                    plugin_id=plugin.id,
                    repo_url=plugin.repo_url,
                )
                logger.info(
                    f"插件 {plugin.plugin_name} 安装成功，版本：{plugin.plugin_version}，耗时：{elapsed_time:.2f} 秒")
                sync_plugins.append(plugin.id)
            else:
                logger.error(
                    f"插件 {plugin.plugin_name} v{plugin.plugin_version} 安装失败：{msg}，耗时：{elapsed_time:.2f} 秒")
                failed_plugins.append(plugin.id)

        if SystemUtils.is_frozen():
            return []

        # 获取已安装插件列表
        install_plugins = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取远程和本地仓库来源插件列表
        online_plugins = self.get_online_plugins()
        local_repo_plugins = self.get_local_repo_plugins()
        candidate_plugins = self.process_plugins_list(online_plugins + local_repo_plugins, []) \
            if online_plugins or local_repo_plugins else []
        # 确定需要安装的插件
        plugins_to_install = [
            plugin for plugin in candidate_plugins
            if plugin.id in install_plugins
            and plugin.system_version_compatible is not False
            and not self.is_plugin_exists(plugin.id, plugin.plugin_version)
        ]

        if not plugins_to_install:
            return []
        logger.info("开始安装第三方插件...")
        sync_plugins = []
        failed_plugins = []

        # 使用 ThreadPoolExecutor 进行并发安装
        total_start_time = time.time()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(install_plugin, plugin): plugin
                for plugin in plugins_to_install
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f"插件 {plugin.plugin_name} 安装过程中出现异常: {exc}")

        total_elapsed_time = time.time() - total_start_time
        logger.info(
            f"第三方插件安装完成，成功：{len(sync_plugins)} 个，"
            f"失败：{len(failed_plugins)} 个，总耗时：{total_elapsed_time:.2f} 秒"
        )
        return sync_plugins

    @staticmethod
    def install_plugin_missing_dependencies() -> List[str]:
        """
        安装插件中缺失或不兼容的依赖项
        """
        pluginhelper = PluginHelper()
        # 第一步：获取需要安装的依赖项列表
        missing_dependencies = pluginhelper.find_missing_dependencies()
        if not missing_dependencies:
            return missing_dependencies
        logger.debug(f"检测到缺失的依赖项: {missing_dependencies}")
        logger.info(f"开始安装缺失的依赖项，共 {len(missing_dependencies)} 个...")
        # 第二步：安装依赖项并返回结果
        total_start_time = time.time()
        success, message = pluginhelper.install_dependencies(missing_dependencies)
        total_elapsed_time = time.time() - total_start_time
        if success:
            logger.info(f"已完成 {len(missing_dependencies)} 个依赖项安装，总耗时：{total_elapsed_time:.2f} 秒")
        else:
            logger.warning(f"存在缺失依赖项安装失败，请尝试手动安装，总耗时：{total_elapsed_time:.2f} 秒")
        return missing_dependencies

    def get_plugin_config(self, pid: str, instance_id: str = DEFAULT_INSTANCE_ID) -> dict:
        """
        获取插件配置
        :param pid: 插件ID
        :param instance_id: 实例ID
        """
        if not self.has_plugin(pid):
            return {}
        conf = PluginConfigOper().get(pid, instance_id)
        if conf:
            # 去掉空Key
            return {k: v for k, v in conf.items() if k}
        return {}

    def save_plugin_config(self, pid: str, conf: dict, force: bool = False,
                           instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        保存插件配置
        :param pid: 插件ID
        :param conf: 配置
        :param force: 强制保存
        :param instance_id: 实例ID
        """
        if not force and not self.has_plugin(pid):
            return False
        PluginConfigOper().set(pid, conf, instance_id)
        return True

    async def async_save_plugin_config(
        self, pid: str, conf: dict, force: bool = False,
        instance_id: str = DEFAULT_INSTANCE_ID
    ) -> bool:
        """
        异步保存插件配置。
        :param pid: 插件ID
        :param conf: 配置
        :param force: 强制保存
        :param instance_id: 实例ID
        """
        if not force and not self.has_plugin(pid):
            return False
        await PluginConfigOper().async_set(pid, conf, instance_id)
        return True

    def delete_plugin_config(self, pid: str, force: bool = False) -> bool:
        """
        删除插件配置，插件的全部实例一并清除
        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化配置
        """
        if not force and not self.has_plugin(pid):
            return False
        return PluginConfigOper().delete_plugin(pid)

    def delete_plugin_data(self, pid: str, force: bool = False) -> bool:
        """
        删除插件数据
        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化数据
        """
        if not force and not self.has_plugin(pid):
            return False
        PluginDataOper().del_data(pid)
        # 删除插件自管理的独立库，失败不影响已完成的数据清理
        try:
            from app.db.plugin import teardown_plugin_database
            teardown_plugin_database(pid)
        except Exception as err:
            logger.error(f"删除插件 {pid} 自管理数据库出错：{str(err)}")
        return True

    def get_plugin_state(self, pid: str) -> bool:
        """
        获取插件状态
        :param pid: 插件ID或实例键
        """
        plugin = self._resolve_running_plugin(pid)
        return plugin.get_state() if plugin else False

    def get_plugin_commands(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件命令
        [{
            "cmd": "/xx",
            "event": EventType.xx,
            "desc": "xxxx",
            "data": {},
            "pid": "",
        }]
        """
        ret_commands = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_command") and ObjectUtils.check_method(plugin.get_command):
                try:
                    if not plugin.get_state():
                        continue
                    commands = plugin.get_command() or []
                    for command in commands:
                        command["pid"] = plugin_id
                    ret_commands.extend(commands)
                except Exception as e:
                    logger.error(f"获取插件命令出错：{str(e)}")
        return ret_commands

    def get_plugin_apis(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件API
        [{
            "path": "/xx",
            "endpoint": self.xxx,
            "methods": ["GET", "POST"],
            "summary": "API名称",
            "description": "API说明",
            "allow_anonymous": false
        }]
        """
        ret_apis = []
        if pid:
            plugins = {key: plugin for key, plugin in self._running_plugins.items()
                       if matches_plugin(key, pid)}
        else:
            plugins = self._running_plugins
        for plugin_id, plugin in plugins.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_api") and ObjectUtils.check_method(plugin.get_api):
                try:
                    apis = plugin.get_api() or []
                    for api in apis:
                        api["path"] = f"/{plugin_id}{api['path']}"
                        if not api.get("auth"):
                            api["auth"] = "apikey"
                    ret_apis.extend(apis)
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} API出错：{str(e)}")
        return ret_apis

    def get_plugin_services(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件服务
        [{
            "id": "服务ID",
            "name": "服务名称",
            "trigger": "触发器：cron、interval、date、CronTrigger.from_crontab()",
            "func": self.xxx,
            "kwargs": {} # 定时器参数,
            "func_kwargs": {} # 方法参数
        }]
        """
        ret_services = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_service") and ObjectUtils.check_method(plugin.get_service):
                try:
                    if not plugin.get_state():
                        continue
                    services = plugin.get_service() or []
                    ret_services.extend(services)
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 服务出错：{str(e)}")
        return ret_services

    def get_plugin_modules(self, pid: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
        """
        获取插件模块

        以实例键为键，同一插件的多个实例各占一条，互不覆盖。
        {
            (实例键, 插件名称): {
                method: function
            }
        }
        """
        ret_modules = {}
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_module") and ObjectUtils.check_method(plugin.get_module):
                try:
                    if not plugin.get_state():
                        continue
                    plugin_module = plugin.get_module() or []
                    if plugin_module:
                        warn_legacy_module_injection(plugin_id)
                    ret_modules[(plugin_id, plugin.get_name())] = plugin_module
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 模块出错：{str(e)}")
        return ret_modules

    def get_plugin_actions(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件动作
        [{
            "id": "动作ID",
            "name": "动作名称",
            "func": self.xxx,
            "kwargs": {} # 需要附加传递的参数
        }]
        """
        ret_actions = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_actions") and ObjectUtils.check_method(plugin.get_actions):
                try:
                    if not plugin.get_state():
                        continue
                    actions = plugin.get_actions()
                    if actions:
                        ret_actions.append({
                            "plugin_id": plugin_id,
                            "plugin_name": plugin.plugin_name,
                            "actions": actions
                        })
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 动作出错：{str(e)}")
        return ret_actions

    @staticmethod
    def _copy_plugin_agent_tools(
        tools_info: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        复制插件智能体工具注册信息，避免调用方修改缓存内容。
        """
        return [
            {
                **plugin_info,
                "tools": list(plugin_info.get("tools", [])),
            }
            for plugin_info in tools_info
        ]

    def get_plugin_agent_tools(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件智能体工具
        [{
            "plugin_id": "插件ID",
            "plugin_name": "插件名称",
            "tools": [ToolClass1, ToolClass2, ...]
        }]
        """
        cache_key = pid or "__all__"
        for _attempt in range(self.AGENT_TOOLS_BUILD_MAX_ATTEMPTS):
            with self._plugin_agent_tools_cache_lock:
                cache_revision = self._plugin_agent_tools_revision
                cached_tools = self._plugin_agent_tools_cache.get(cache_key)
            if cached_tools is not None:
                return self._copy_plugin_agent_tools(cached_tools)

            ret_tools = []
            # 创建字典快照避免并发修改
            running_plugins_snapshot = dict(self._running_plugins)
            for plugin_id, plugin in running_plugins_snapshot.items():
                if not matches_plugin(plugin_id, pid):
                    continue
                if hasattr(plugin, "get_agent_tools") and ObjectUtils.check_method(
                    plugin.get_agent_tools
                ):
                    try:
                        if not plugin.get_state():
                            continue
                        tools = plugin.get_agent_tools()
                        if tools:
                            ret_tools.append({
                                "plugin_id": plugin_id,
                                "plugin_name": plugin.plugin_name,
                                "tools": tools
                            })
                    except Exception as e:
                        logger.error(f"获取插件 {plugin_id} 智能体工具出错：{str(e)}")
            with self._plugin_agent_tools_cache_lock:
                if cache_revision != self._plugin_agent_tools_revision:
                    # 插件状态在注册表构建期间发生变化，重新读取以避免写回过期快照。
                    continue
                self._plugin_agent_tools_cache[cache_key] = self._copy_plugin_agent_tools(
                    ret_tools
                )
                return ret_tools
        raise RuntimeError("插件工具注册表持续变化，无法建立当前快照")

    @staticmethod
    def get_plugin_remote_entry(plugin_id: str, dist_path: str) -> str:
        """
        获取插件的远程入口地址
        :param plugin_id: 插件 ID
        :param dist_path: 插件的分发路径
        :return: 远程入口地址
        """
        dist_path = dist_path.strip("/")
        path = posixpath.join(
            "plugin",
            "file",
            plugin_id.lower(),
            dist_path,
            "remoteEntry.js",
        )
        if not path.startswith("/"):
            path = "/" + path
        return path

    def get_plugin_remotes(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件联邦组件列表
        """
        remotes = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_render_mode"):
                render_mode, dist_path = plugin.get_render_mode()
                if render_mode != "vue":
                    continue
                remotes.append({
                    "id": plugin_id,
                    "url": self.get_plugin_remote_entry(plugin_id, dist_path),
                    "name": plugin.plugin_name,
                })
        return remotes

    def get_plugin_auth_providers(self) -> List[Dict[str, Any]]:
        """
        聚合插件声明的登录认证提供方。

        :return: 插件认证入口列表
        """
        providers: List[Dict[str, Any]] = []
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not plugin.get_state():
                continue
            if not hasattr(plugin, "get_auth_providers") or not ObjectUtils.check_method(plugin.get_auth_providers):
                continue
            try:
                plugin_providers = plugin.get_auth_providers() or []
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} 登录认证提供方出错：{str(e)}")
                continue
            render_mode = None
            dist_path = None
            if hasattr(plugin, "get_render_mode"):
                render_mode, dist_path = plugin.get_render_mode()
            for raw_provider in plugin_providers:
                if not raw_provider or not isinstance(raw_provider, dict):
                    continue
                provider = raw_provider.copy()
                provider["type"] = "plugin"
                provider["plugin_id"] = plugin_id
                provider.setdefault("id", f"plugin:{plugin_id}")
                provider.setdefault("name", plugin.plugin_name)
                provider.setdefault("enabled", True)
                if render_mode == "vue" and dist_path:
                    provider.setdefault("component", "AuthPage")
                    provider["remote"] = {
                        "id": plugin_id,
                        "url": self.get_plugin_remote_entry(plugin_id, dist_path),
                        "name": plugin.plugin_name,
                    }
                providers.append(provider)
        return providers

    def get_plugin_sidebar_nav(self) -> List[Dict[str, Any]]:
        """
        聚合所有已启用 Vue 插件的侧栏导航项（get_sidebar_nav）。
        """
        valid_sections = {"start", "discovery", "subscribe", "organize", "system"}
        valid_permissions = {"subscribe", "discovery", "search", "manage", "admin"}
        items: List[Dict[str, Any]] = []
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not plugin.get_state():
                continue
            if not hasattr(plugin, "get_sidebar_nav") or not ObjectUtils.check_method(plugin.get_sidebar_nav):
                continue
            if not hasattr(plugin, "get_render_mode"):
                continue
            render_mode, _ = plugin.get_render_mode()
            if render_mode != "vue":
                continue
            try:
                nav_list = plugin.get_sidebar_nav()
                if not nav_list:
                    continue
                for raw in nav_list:
                    if not raw or not isinstance(raw, dict):
                        continue
                    nav_key = str(raw.get("nav_key") or raw.get("key") or "main").strip()
                    if not nav_key or any(c in nav_key for c in ["/", "?", "#", " "]):
                        logger.warning(f"插件[{plugin_id}]侧栏项 nav_key 无效，已跳过: {nav_key!r}")
                        continue
                    title = raw.get("title") or plugin.plugin_name
                    icon = raw.get("icon") or "mdi-puzzle"
                    section = str(raw.get("section") or "system").lower()
                    if section not in valid_sections:
                        section = "system"
                    perm = raw.get("permission")
                    if perm is not None and str(perm) not in valid_permissions:
                        perm = None
                    else:
                        perm = str(perm) if perm is not None else None
                    order = raw.get("order", 0)
                    try:
                        order = int(order)
                    except (TypeError, ValueError):
                        order = 0
                    items.append({
                        "plugin_id": plugin_id,
                        "nav_key": nav_key,
                        "title": title,
                        "icon": icon,
                        "section": section,
                        "permission": perm,
                        "order": order,
                    })
            except Exception as e:
                logger.error(f"获取插件[{plugin_id}]侧栏导航出错：{str(e)}")
        items.sort(key=lambda x: (x["section"], x["order"], x["plugin_id"], x["nav_key"]))
        return items

    def get_plugin_dashboard_meta(self) -> List[Dict[str, str]]:
        """
        获取所有插件仪表盘元信息
        """
        dashboard_meta = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not hasattr(plugin, "get_dashboard") or not ObjectUtils.check_method(plugin.get_dashboard):
                continue
            try:
                if not plugin.get_state():
                    continue
                # 如果是多仪表盘实现
                if hasattr(plugin, "get_dashboard_meta") and ObjectUtils.check_method(plugin.get_dashboard_meta):
                    meta = plugin.get_dashboard_meta()
                    if meta:
                        dashboard_meta.extend([{
                            "id": plugin_id,
                            "name": m.get("name"),
                            "key": m.get("key"),
                        } for m in meta if m])
                else:
                    dashboard_meta.append({
                        "id": plugin_id,
                        "name": plugin.plugin_name,
                        "key": "",
                    })
            except Exception as e:
                logger.error(f"获取插件[{plugin_id}]仪表盘元数据出错：{str(e)}")
        return dashboard_meta

    def get_plugin_dashboard(self, pid: str, key: str, user_agent: str = None) -> Optional[schemas.PluginDashboard]:
        """
        获取插件仪表盘
        """

        def __get_params_count(func: Callable):
            """
            获取函数的参数信息
            """
            signature = inspect.signature(func)
            return len(signature.parameters)

        # 获取插件实例
        plugin_instance = self._resolve_running_plugin(pid)
        if not plugin_instance:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"插件 {pid} 不存在或未加载")

        # 渲染模式
        render_mode, _ = plugin_instance.get_render_mode()
        # 获取插件仪表板
        try:
            # 检查方法的参数个数
            params_count = __get_params_count(plugin_instance.get_dashboard)
            if params_count > 1:
                dashboard: Tuple = plugin_instance.get_dashboard(key=key, user_agent=user_agent)
            elif params_count > 0:
                dashboard: Tuple = plugin_instance.get_dashboard(user_agent=user_agent)
            else:
                dashboard: Tuple = plugin_instance.get_dashboard()
        except Exception as e:
            logger.error(f"插件 {pid} 调用方法 get_dashboard 出错: {str(e)}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"插件 {pid} 调用方法 get_dashboard 出错: {str(e)}")
        if dashboard is None:
            return None
        if not isinstance(dashboard, (tuple, list)) or len(dashboard) != 3:
            logger.error(f"插件 {pid} 返回的仪表盘数据格式错误")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"插件 {pid} 返回的仪表盘数据格式错误")
        cols, attrs, elements = dashboard
        return schemas.PluginDashboard(
            id=pid,
            name=plugin_instance.plugin_name,
            key=key,
            render_mode=render_mode,
            cols=cols or {},
            attrs=attrs or {},
            elements=elements
        )

    def get_plugin_attr(self, pid: str, attr: str) -> Any:
        """
        获取插件属性
        :param pid: 插件ID或实例键
        :param attr: 属性名
        """
        plugin = self._resolve_running_plugin(pid)
        if not plugin:
            return None
        if not hasattr(plugin, attr):
            return None
        return getattr(plugin, attr)

    def run_plugin_method(self, pid: str, method: str, *args, **kwargs) -> Any:
        """
        运行插件方法
        :param pid: 插件ID或实例键
        :param method: 方法名
        :param args: 参数
        :param kwargs: 关键字参数
        """
        plugin = self._resolve_running_plugin(pid)
        if not plugin:
            return None
        if not hasattr(plugin, method):
            return None
        return getattr(plugin, method)(*args, **kwargs)

    async def async_run_plugin_method(self, pid: str, method: str, *args, **kwargs) -> Any:
        """
        异步运行插件方法
        :param pid: 插件ID或实例键
        :param method: 方法名
        :param args: 参数
        :param kwargs: 关键字参数
        """
        plugin = self._resolve_running_plugin(pid)
        if not plugin:
            return None
        if not hasattr(plugin, method):
            return None
        method_func = getattr(plugin, method)
        if asyncio.iscoroutinefunction(method_func):
            return await method_func(*args, **kwargs)
        else:
            return method_func(*args, **kwargs)

    def get_plugin_ids(self) -> List[str]:
        """
        获取所有插件ID，同一插件的多个实例只出现一次
        """
        return self._distinct_plugin_ids(self._plugins)

    def get_running_plugin_ids(self) -> List[str]:
        """
        获取所有运行态插件ID，同一插件的多个实例只出现一次
        """
        return self._distinct_plugin_ids(self._running_plugins)

    def get_online_plugins(self, force: bool = False) -> List[schemas.Plugin]:
        """
        获取所有在线插件信息
        """
        if not settings.PLUGIN_MARKET:
            return []

        # 拉取当前索引及可扫描的旧索引；旧条目可用当前版本 false 显式排除。
        compatible_flags = (
            [settings.VERSION_FLAG] + VERSION_BACKWARD_COMPATIBLE_FLAGS.get(settings.VERSION_FLAG, [])
            if settings.VERSION_FLAG else []
        )
        markets = [m for m in settings.PLUGIN_MARKET.split(",") if m]

        # 使用多线程获取线上插件
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # future -> (market_index, is_higher, flag_priority)
            futures_meta: Dict[concurrent.futures.Future, Tuple[int, bool, int]] = {}
            for market_index, m in enumerate(markets):
                # 默认索引只展示声明 V2 或当前版本兼容的共享实现。
                base_future = executor.submit(self.get_plugins_from_market, m, None, force)
                futures_meta[base_future] = (market_index, False, 0)
                # 提交当前专用索引（如 v3）及可扫描的旧索引（如 v2）。
                for flag_priority, flag in enumerate(compatible_flags):
                    higher_future = executor.submit(self.get_plugins_from_market, m, flag, force)
                    futures_meta[higher_future] = (market_index, True, flag_priority)

            # 收集结果，按市场顺序、高版本优先、兼容版本优先级排序，保证去重时优先保留高版本来源
            collected: List[Tuple[int, bool, int, List[schemas.Plugin]]] = []
            for future in concurrent.futures.as_completed(futures_meta):
                plugins = future.result()
                market_index, is_higher, flag_priority = futures_meta[future]
                collected.append((market_index, is_higher, flag_priority, plugins or []))

        collected.sort(key=lambda item: (item[0], 0 if item[1] else 1, item[2]))
        higher_version_plugins: List[schemas.Plugin] = []
        base_version_plugins: List[schemas.Plugin] = []
        for _market_index, is_higher, _flag_priority, plugins in collected:
            if not plugins:
                continue
            if is_higher:
                higher_version_plugins.extend(plugins)
            else:
                base_version_plugins.extend(plugins)

        result = self.process_plugins_list(higher_version_plugins, base_version_plugins)
        logger.info(f"获取到 {len(result)} 个线上插件")
        return result

    def get_local_plugins(self) -> List[schemas.Plugin]:
        """
        获取所有本地已下载的插件信息
        """
        # 返回值
        plugins = []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        for pid in self._distinct_plugin_ids(self._plugins):
            plugin_class = self._get_plugin_class(pid)
            # 运行状插件
            plugin_obj = self._resolve_running_plugin(pid)
            # 基本属性
            plugin = schemas.Plugin()
            # ID
            plugin.id = pid
            # 安装状态
            if pid in installed_apps:
                plugin.installed = True
            else:
                plugin.installed = False
            # 运行状态
            if plugin_obj and hasattr(plugin_obj, "get_state"):
                try:
                    state = plugin_obj.get_state()
                except Exception as e:
                    logger.error(f"获取插件 {pid} 状态出错：{str(e)}")
                    state = False
                plugin.state = state
            else:
                plugin.state = False
            # 是否有详情页面
            if hasattr(plugin_class, "get_page"):
                if ObjectUtils.check_method(plugin_class.get_page):
                    plugin.has_page = True
                else:
                    plugin.has_page = False
            # 公钥
            if hasattr(plugin_class, "plugin_public_key"):
                plugin.plugin_public_key = plugin_class.plugin_public_key
            # 权限
            if not self.__set_and_check_auth_level(plugin=plugin, source=plugin_class):
                continue
            # 名称
            if hasattr(plugin_class, "plugin_name"):
                plugin.plugin_name = plugin_class.plugin_name
            # 描述
            if hasattr(plugin_class, "plugin_desc"):
                plugin.plugin_desc = plugin_class.plugin_desc
            # 版本
            if hasattr(plugin_class, "plugin_version"):
                plugin.plugin_version = plugin_class.plugin_version
            # 图标
            if hasattr(plugin_class, "plugin_icon"):
                plugin.plugin_icon = plugin_class.plugin_icon
            # 作者
            if hasattr(plugin_class, "plugin_author"):
                plugin.plugin_author = plugin_class.plugin_author
            # 作者链接
            if hasattr(plugin_class, "author_url"):
                plugin.author_url = plugin_class.author_url
            # 加载顺序
            if hasattr(plugin_class, "plugin_order"):
                plugin.plugin_order = plugin_class.plugin_order
            # 是否需要更新
            plugin.has_update = False
            # 本地标志
            plugin.is_local = True
            # 汇总
            plugins.append(plugin)
        # 根据加载排序重新排序
        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        return plugins

    def get_local_plugin_version(self, pid: str) -> Optional[str]:
        """
        获取指定已安装插件的本地版本，不触发全部插件的状态、页面和权限计算。

        插件类由运行期动态加载，旧插件可能未声明版本属性，因此缺失时返回 None。
        """
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        if pid not in installed_apps:
            return None
        plugin_class = self._get_plugin_class(pid)
        if not plugin_class:
            return None
        return getattr(plugin_class, "plugin_version", None)

    def get_local_repo_plugins(self) -> List[schemas.Plugin]:
        """
        获取本地插件仓库目录中的插件信息
        """
        plugins = []
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        local_candidates = PluginHelper().get_local_plugin_candidates()
        if not local_candidates:
            return []
        for pid, plugin_info in local_candidates.items():
            package_version = plugin_info.get("package_version")
            plugin = self._process_plugin_info(
                pid=pid,
                plugin_info=plugin_info,
                market=PluginHelper.make_local_repo_url(
                    pid,
                    plugin_info.get("repo_path"),
                    package_version
                ),
                installed_apps=installed_apps,
                add_time=0,
                package_version=package_version
            )
            if not plugin:
                continue
            plugin.is_local = True
            plugins.append(plugin)

        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        logger.info(f"获取到 {len(plugins)} 个本地插件")
        return plugins

    @staticmethod
    def is_plugin_exists(pid: str, version: str = None) -> bool:
        """
        判断插件是否存在，并满足版本要求(有传入version时)
        :param pid: 插件ID
        :param version: 插件版本
        """
        if not pid:
            return False
        try:
            # 构建包名
            package_name = f"app.plugins.{pid.lower()}"
            # 检查包是否存在
            spec = importlib.util.find_spec(package_name)
            package_exists = spec is not None and spec.origin is not None
            logger.debug(f"{pid} exists: {package_exists}")
            if not package_exists:
                return False

            local_version = PluginManager().get_plugin_attr(pid=pid, attr="plugin_version")
            if not local_version:
                return False

            if version and not compare_version(local_version, ">=", version):
                logger.warn(f"Plugin {pid} version: {local_version} (older than version: {version})")
                return False

            return True
        except Exception as e:
            logger.debug(f"获取插件是否在本地包中存在失败，{e}")
            return False

    def get_plugins_from_market(self, market: str,
                                package_version: Optional[str] = None,
                                force: bool = False) -> Optional[List[schemas.Plugin]]:
        """
        从指定的市场获取插件信息
        :param market: 市场的 URL 或标识
        :param package_version: 首选插件版本 (如 "v2", "v3")，如果不指定则获取 v1 版本
        :param force: 是否强制刷新（忽略缓存）
        :return: 返回插件的列表，若获取失败返回 []
        """
        if not market:
            return []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取在线插件
        with fresh(force):
            online_plugins = PluginHelper().get_plugins(market, package_version)
        if online_plugins is None:
            logger.warning(
                f"获取{package_version if package_version else ''}插件库失败：{market}，请检查 GitHub 网络连接")
            return []
        ret_plugins = []
        add_time = len(online_plugins)
        for pid, plugin_info in online_plugins.items():
            plugin = self._process_plugin_info(pid, plugin_info, market, installed_apps, add_time, package_version)
            if plugin:
                ret_plugins.append(plugin)
            add_time -= 1

        return ret_plugins

    @staticmethod
    def process_plugins_list(higher_version_plugins: List[schemas.Plugin],
                             base_version_plugins: List[schemas.Plugin]) -> List[schemas.Plugin]:
        """
        处理插件列表：合并、去重、排序、保留最高版本
        :param higher_version_plugins: 高版本插件列表
        :param base_version_plugins: 基础版本插件列表
        :return: 处理后的插件列表
        """
        # 优先处理高版本插件
        all_plugins = []
        all_plugins.extend(higher_version_plugins)
        # 将未出现在高版本插件列表中的 v1 插件加入 all_plugins
        higher_plugin_ids = {f"{p.id}{p.plugin_version}" for p in higher_version_plugins}
        all_plugins.extend([p for p in base_version_plugins if f"{p.id}{p.plugin_version}" not in higher_plugin_ids])
        markets = [item for item in settings.PLUGIN_MARKET.split(",") if item]

        def repo_order(plugin: schemas.Plugin) -> int:
            if PluginHelper.is_local_repo_url(plugin.repo_url):
                return len(markets) + 1
            if plugin.repo_url in markets:
                return markets.index(plugin.repo_url)
            return len(markets)

        # 去重：同 ID + 版本优先保留市场来源，其次按来源顺序稳定保留。
        dedup_plugins = {}
        for plugin in sorted(all_plugins, key=repo_order):
            key = f"{plugin.id}{plugin.plugin_version}"
            exists = dedup_plugins.get(key)
            if not exists:
                dedup_plugins[key] = plugin
                continue
            if PluginHelper.is_local_repo_url(exists.repo_url) and not PluginHelper.is_local_repo_url(plugin.repo_url):
                dedup_plugins[key] = plugin

        # 相同 ID 的插件保留版本号最大的版本；同版本市场来源优先。
        result_by_id = {}
        for plugin in sorted(dedup_plugins.values(), key=repo_order):
            exists = result_by_id.get(plugin.id)
            if not exists:
                result_by_id[plugin.id] = plugin
                continue
            if compare_version(plugin.plugin_version, ">", exists.plugin_version):
                result_by_id[plugin.id] = plugin
            elif plugin.plugin_version == exists.plugin_version \
                    and PluginHelper.is_local_repo_url(exists.repo_url) \
                    and not PluginHelper.is_local_repo_url(plugin.repo_url):
                result_by_id[plugin.id] = plugin

        return list(result_by_id.values())

    def _process_plugin_info(self, pid: str, plugin_info: dict, market: str,
                             installed_apps: List[str], add_time: int,
                             package_version: Optional[str] = None) -> Optional[schemas.Plugin]:
        """
        处理单个插件信息，创建 schemas.Plugin 对象
        :param pid: 插件ID
        :param plugin_info: 插件信息字典
        :param market: 市场URL
        :param installed_apps: 已安装插件列表
        :param add_time: 添加顺序
        :param package_version: 包版本
        :return: 创建的插件对象，如果验证失败返回None
        """
        if not isinstance(plugin_info, dict):
            return None

        plugin_info = PluginHelper.annotate_plugin_system_version(plugin_info.copy())
        if not PluginHelper.is_package_plugin_compatible(
                plugin_info, package_version or ""
        ):
            # 插件当前版本不兼容
            return None

        # 运行状插件
        plugin_obj = self._resolve_running_plugin(pid)
        # 非运行态插件
        plugin_static = self._get_plugin_class(pid)
        # 基本属性
        plugin = schemas.Plugin()
        # ID
        plugin.id = pid
        # 安装状态
        if pid in installed_apps and plugin_static:
            plugin.installed = True
        else:
            plugin.installed = False
        # 是否有新版本
        plugin.has_update = False
        if plugin_static:
            installed_version = getattr(plugin_static, "plugin_version")
            if compare_version(installed_version, "<", plugin_info.get("version")):
                # 需要更新
                plugin.has_update = True
        # 主系统版本兼容性
        if plugin_info.get("system_version"):
            plugin.system_version = plugin_info.get("system_version")
        if plugin_info.get("system_version_compatible") is False:
            plugin.system_version_compatible = False
            plugin.system_version_message = plugin_info.get("system_version_message")
        # 运行状态
        if plugin_obj and hasattr(plugin_obj, "get_state"):
            try:
                state = plugin_obj.get_state()
            except Exception as e:
                logger.error(f"获取插件 {pid} 状态出错：{str(e)}")
                state = False
            plugin.state = state
        else:
            plugin.state = False
        # 是否有详情页面
        plugin.has_page = False
        if plugin_obj and hasattr(plugin_obj, "get_page"):
            if ObjectUtils.check_method(plugin_obj.get_page):
                plugin.has_page = True
        # 公钥
        if plugin_info.get("key"):
            plugin.plugin_public_key = plugin_info.get("key")
        # 权限
        if not self.__set_and_check_auth_level(plugin=plugin, source=plugin_info):
            return None
        # 名称
        if plugin_info.get("name"):
            plugin.plugin_name = plugin_info.get("name")
        # 描述
        if plugin_info.get("description"):
            plugin.plugin_desc = plugin_info.get("description")
        # 版本
        if plugin_info.get("version"):
            plugin.plugin_version = plugin_info.get("version")
        # 图标
        if plugin_info.get("icon"):
            plugin.plugin_icon = plugin_info.get("icon")
        # 标签
        plugin.plugin_label = self._normalize_plugin_label(plugin_info.get("labels"))
        # 作者
        if plugin_info.get("author"):
            plugin.plugin_author = plugin_info.get("author")
        # 更新历史
        if plugin_info.get("history"):
            plugin.history = plugin_info.get("history")
        # Release 能力位来自插件市场索引，用于前端展示和后端安装入口双重校验。
        plugin.release = bool(plugin_info.get("release"))
        # 仓库链接
        plugin.repo_url = market
        # 本地标志
        plugin.is_local = False
        # 添加顺序
        plugin.add_time = add_time

        return plugin

    @staticmethod
    def _normalize_plugin_label(labels: Any) -> Optional[str]:
        """
        规整插件市场标签字段，兼容旧字符串和新列表格式。

        :param labels: 插件市场 package 中的 labels 字段
        :return: 用空格拼接后的标签字符串，无法识别或为空时返回 None
        """
        if isinstance(labels, str):
            label = labels.strip()
            return label or None
        if isinstance(labels, list):
            normalized_labels = [str(item).strip() for item in labels if str(item).strip()]
            return " ".join(normalized_labels) or None
        return None

    async def async_get_online_plugins(
            self,
            force: bool = False,
            progress_callback: Optional[Callable[..., None]] = None,
    ) -> List[schemas.Plugin]:
        """
        异步获取所有在线插件信息
        :param force: 是否强制刷新（忽略缓存）
        :param progress_callback: 定时服务进度更新回调
        """
        if not settings.PLUGIN_MARKET:
            if progress_callback:
                progress_callback(value=100, text="未配置插件市场，跳过刷新")
            return []

        async def fetch_market(
                market: str,
                package_version: Optional[str],
                result_version: str,
                task_index: int,
        ) -> Tuple[int, str, List[schemas.Plugin]]:
            """
            获取单个市场版本的插件列表并保留结果分组。
            """
            plugins = await self.async_get_plugins_from_market(
                market,
                package_version,
                force,
            )
            return task_index, result_version, plugins or []

        higher_version_plugins = []
        base_version_plugins = []
        tasks = []

        # 拉取当前索引及可扫描的旧索引；旧条目可用当前版本 false 显式排除。
        compatible_flags = (
            [settings.VERSION_FLAG] + VERSION_BACKWARD_COMPATIBLE_FLAGS.get(settings.VERSION_FLAG, [])
            if settings.VERSION_FLAG else []
        )
        for market in settings.PLUGIN_MARKET.split(","):
            if not market:
                continue
            tasks.append(
                asyncio.create_task(
                    fetch_market(market, None, "base_version", len(tasks))
                )
            )
            for flag in compatible_flags:
                tasks.append(
                    asyncio.create_task(
                        fetch_market(
                            market,
                            flag,
                            "higher_version",
                            len(tasks),
                        )
                    )
                )

        if tasks:
            total_tasks = len(tasks)
            finished_tasks = 0
            task_results = {}
            if progress_callback:
                progress_callback(
                    value=0,
                    text=f"开始刷新插件市场，共 {total_tasks} 个请求 ...",
                    data={"total": total_tasks, "finished": 0},
                )
            for completed_task in asyncio.as_completed(tasks):
                try:
                    task_index, version, plugins = await completed_task
                    task_results[task_index] = (version, plugins)
                except Exception as err:
                    logger.error(f"获取插件市场数据失败：{str(err)}")
                finished_tasks += 1
                if progress_callback:
                    progress_callback(
                        value=finished_tasks / total_tasks * 100,
                        text=(
                            f"插件市场请求"
                            f"（{finished_tasks}/{total_tasks}）处理完成"
                        ),
                        data={"total": total_tasks, "finished": finished_tasks},
                    )
            for task_index in sorted(task_results):
                version, plugins = task_results[task_index]
                if plugins:
                    if version == "higher_version":
                        higher_version_plugins.extend(plugins)
                    else:
                        base_version_plugins.extend(plugins)

        result = self.process_plugins_list(higher_version_plugins, base_version_plugins)
        logger.info(f"获取到 {len(result)} 个线上插件")
        if progress_callback:
            progress_callback(value=100, text="插件市场缓存刷新完成")
        return result

    async def async_get_plugins_from_market(self, market: str,
                                            package_version: Optional[str] = None,
                                            force: bool = False) -> Optional[List[schemas.Plugin]]:
        """
        异步从指定的市场获取插件信息
        :param market: 市场的 URL 或标识
        :param package_version: 首选插件版本 (如 "v2", "v3")，如果不指定则获取 v1 版本
        :param force: 是否强制刷新（忽略缓存）
        :return: 返回插件的列表，若获取失败返回 []
        """
        if not market:
            return []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取在线插件
        async with async_fresh(force):
            online_plugins = await PluginHelper().async_get_plugins(market, package_version)
        if online_plugins is None:
            logger.warning(
                f"获取{package_version if package_version else ''}插件库失败：{market}，请检查 GitHub 网络连接")
            return []
        ret_plugins = []
        add_time = len(online_plugins)
        for pid, plugin_info in online_plugins.items():
            plugin = self._process_plugin_info(pid, plugin_info, market, installed_apps, add_time, package_version)
            if plugin:
                ret_plugins.append(plugin)
            add_time -= 1

        return ret_plugins

    @staticmethod
    def __set_and_check_auth_level(plugin: Union[schemas.Plugin, Type[Any]],
                                   source: Optional[Union[dict, Type[Any]]] = None) -> bool:
        """
        设置并检查插件的认证级别
        :param plugin: 插件对象或包含 auth_level 属性的对象
        :param source: 可选的字典对象或类对象，可能包含 "level" 或 "auth_level" 键
        :return: 如果插件的认证级别有效且当前环境的认证级别满足要求，返回 True，否则返回 False
        """
        # 检查并赋值 source 中的 level 或 auth_level
        if source:
            if isinstance(source, dict) and "level" in source:
                plugin.auth_level = source.get("level")
            elif hasattr(source, "auth_level"):
                plugin.auth_level = source.auth_level
        # 如果 source 为空且 plugin 本身没有 auth_level，直接返回 True
        elif not hasattr(plugin, "auth_level"):
            return True

        # auth_level 级别说明
        # 1 - 所有用户可见
        # 2 - 站点认证用户可见
        # 3 - 站点&密钥认证可见
        # 99 - 站点&特殊密钥认证可见
        # 如果当前站点认证级别大于 1 且插件级别为 99，并存在插件公钥，说明为特殊密钥认证，通过密钥匹配进行认证
        auth_level = _site_auth_level_provider()
        if auth_level > 1 and plugin.auth_level == 99 and hasattr(plugin, "plugin_public_key"):
            plugin_id = plugin.id if isinstance(plugin, schemas.Plugin) else plugin.__name__
            public_key = plugin.plugin_public_key
            if public_key:
                private_key = PluginManager.__get_plugin_private_key(plugin_id)
                verify = RSAUtils.verify_rsa_keys(public_key=public_key, private_key=private_key)
                return verify
        # 如果当前站点认证级别小于插件级别，则返回 False
        if auth_level < plugin.auth_level:
            return False
        return True

    @staticmethod
    def __get_plugin_private_key(plugin_id: str) -> Optional[str]:
        """
        根据插件标识获取对应的私钥
        :param plugin_id: 插件标识
        :return: 对应的插件私钥，如果未找到则返回 None
        """
        try:
            # 将插件标识转换为大写并构建环境变量名称
            env_var_name = f"PLUGIN_{plugin_id.upper()}_PRIVATE_KEY"
            private_key = os.environ.get(env_var_name)
            return private_key
        except Exception as e:
            logger.debug(f"获取插件 {plugin_id} 的私钥时发生错误：{e}")
            return None
