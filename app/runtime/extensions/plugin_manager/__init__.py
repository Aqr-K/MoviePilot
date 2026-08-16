"""插件管理器。

各功能域按 mixin 分文件，本模块保留插件注册表本身与其生命周期，并对外维持与拆分前
一致的导入面。共享依赖与可注入服务集中在 ``_shared``，各域单向依赖它。
"""
import asyncio
import threading
import traceback
from typing import Any, Dict, List, Optional, Type

from app.foundation.singleton import Singleton
from app.runtime.events import eventmanager
from app.runtime.log import logger
from app.runtime.reload import ConfigReloadMixin
from app.schemas.types import SystemConfigKey

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.runtime.extensions import plugin_shared as _shared
from app.runtime.extensions.plugin_instance import instance_key
from app.runtime.extensions.plugin_shared import (
    configure_plugin_install_reporter,
    configure_plugin_legacy_import_services,
    configure_plugin_resource_import_preparer,
    configure_site_auth_level_provider,
)
from app.runtime.extensions.plugin_manager._loader import _PluginLoaderMixin
from app.runtime.extensions.plugin_manager._watcher import _PluginWatcherMixin
from app.runtime.extensions.plugin_manager._configs import _PluginConfigMixin
from app.runtime.extensions.plugin_manager._capabilities import _PluginCapabilityMixin
from app.runtime.extensions.plugin_manager._ui import _PluginUIMixin
from app.runtime.extensions.plugin_manager._catalog import _PluginCatalogMixin
from app.runtime.extensions.plugin_manager._instances import _PluginInstanceMixin
from app.runtime.extensions.plugin_manager._registry import _PluginRegistryMixin

__all__ = [
    "PluginManager",
    "configure_plugin_install_reporter",
    "configure_plugin_legacy_import_services",
    "configure_plugin_resource_import_preparer",
    "configure_site_auth_level_provider",
]


class PluginManager(
    _PluginRegistryMixin,
    _PluginInstanceMixin,
    _PluginLoaderMixin,
    _PluginWatcherMixin,
    _PluginConfigMixin,
    _PluginCapabilityMixin,
    _PluginUIMixin,
    _PluginCatalogMixin,
    ConfigReloadMixin,
    metaclass=Singleton,
):
    """插件管理器"""
    CONFIG_WATCH = {"DEV", "PLUGIN_AUTO_RELOAD", "PLUGIN_LOCAL_REPO_PATHS"}
    AGENT_TOOLS_BUILD_MAX_ATTEMPTS = 3

    def __init__(self):
        """初始化插件注册表、缓存和开发模式监控状态。"""
        # 插件列表
        self._plugins: dict = {}
        # 运行态插件列表
        self._running_plugins: dict = {}
        # 配置Key
        self._config_key: str = "plugin.%s"
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
        if _shared.settings.DEV or _shared.settings.PLUGIN_AUTO_RELOAD:
            self._start_monitor()

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

        _shared._legacy_diagnostics_configurator(
            enabled=_shared.settings.DEBUG,
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
        installed_plugins = _shared.SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 扫描插件目录，只加载符合条件的插件
        plugins = self._load_selective_plugins(pid, installed_plugins, check_module)
        # 排序
        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        for plugin in plugins:
            plugin_id = plugin.__name__
            if pid and plugin_id != pid:
                continue
            # 判断插件是否满足认证要求，如不满足则不进行实例化
            if not self._set_and_check_auth_level(plugin=plugin):
                # 如果是插件热更新实例，这里则进行替换
                for key in self.get_instance_keys(plugin_id):
                    self._plugins[key] = plugin
                continue
            # 逐个拉起该插件已配置的实例
            for instance_id in self._list_instance_ids(plugin_id):
                self._start_instance(plugin, plugin_id, instance_id)
        self.clear_plugin_agent_tools_cache()

    def _start_instance(self, plugin_class: Type[Any], plugin_id: str, instance_id: str) -> bool:
        """
        拉起插件的一个实例并登记其事件处理器

        :param plugin_class: 插件类
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 是否进入运行态
        """
        key = instance_key(plugin_id, instance_id)
        try:
            # 存储Class
            self._plugins[key] = plugin_class
            # 生成实例
            plugin_obj = self._instantiate_plugin(plugin_class, plugin_id, instance_id)
            # 生效插件配置
            plugin_obj.init_plugin(self.get_plugin_config(plugin_id, instance_id))
            # 存储运行实例
            self._running_plugins[key] = plugin_obj
            logger.info(f"加载插件：{key} 版本：{plugin_obj.plugin_version}")
            # 启用的插件实例才设置事件注册状态可用
            if plugin_obj.get_state():
                eventmanager.enable_event_handler(plugin_class, key)
            else:
                eventmanager.disable_event_handler(plugin_class, key)
            self._sync_plugin_modules(key, plugin_obj)
            return True
        except Exception as err:
            logger.error(f"加载插件 {key} 出错：{str(err)} - {traceback.format_exc()}")
            return False

    def start_instance(self, plugin_id: str, instance_id: str) -> bool:
        """
        单独拉起插件的一个实例，同插件其余实例保持运行不受影响

        插件类取自已加载的注册表而不重扫插件目录，因此不会替换兄弟实例正在使用的类对象。

        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 是否进入运行态
        :raises ValueError: 实例标识含非法字符或超长
        """
        normalized = normalize_instance_id(instance_id)
        plugin_class = self.get_plugin_class(plugin_id)
        if plugin_class is None:
            logger.error(f"插件 {plugin_id} 未加载，无法拉起实例 {normalized}")
            return False
        if not self._set_and_check_auth_level(plugin=plugin_class):
            logger.warning(f"插件 {plugin_id} 不满足认证要求，实例 {normalized} 不拉起")
            return False
        started = self._start_instance(plugin_class, plugin_id, normalized)
        self.clear_plugin_agent_tools_cache()
        return started

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
            logger.error(f"初始化插件 {key} 自管理数据库出错：{str(err)}")
        # 检查插件实例状态并启用/禁用事件处理器
        if plugin.get_state():
            # 启用该实例的事件处理器
            eventmanager.enable_event_handler(type(plugin), key)
        else:
            # 禁用该实例的事件处理器
            eventmanager.disable_event_handler(type(plugin), key)
        # 配置变更可能改变插件启停状态与模块声明，按当前声明重新同步
        self._sync_plugin_modules(key, plugin)
        self.clear_plugin_agent_tools_cache()

    @staticmethod
    def _unregister_plugin_modules(plugin_id: str) -> None:
        """
        摘除某插件注册的全部系统模块

        :param plugin_id: 插件ID，即模块注册来源
        """
        from app.runtime.extensions.module_manager import ModuleManager

        try:
            ModuleManager().unregister_modules(plugin_id)
        except Exception as err:
            logger.error(f"摘除插件 {plugin_id} 的模块出错：{str(err)}")

    def _sync_plugin_modules(self, plugin_id: str, plugin_obj: Any) -> None:
        """
        按插件声明同步其提供的系统模块

        每次同步先摘除该插件上一轮注册的模块再按当前声明登记，因此重复调用为幂等更新；
        插件处于停用态时只摘除不登记。声明或注册出错不影响插件其它功能。

        :param plugin_id: 插件ID，同时作为模块注册来源
        :param plugin_obj: 插件运行实例
        """
        from app.runtime.extensions.module_manager import ModuleManager

        self._unregister_plugin_modules(plugin_id)
        try:
            if not plugin_obj.get_state():
                return
        except Exception as err:
            logger.debug(f"读取插件 {plugin_id} 状态出错，跳过模块注册：{str(err)}")
            return
        hook = getattr(plugin_obj, "provides_modules", None)
        if not callable(hook):
            return
        try:
            declarations = hook() or []
        except Exception as err:
            logger.error(f"读取插件 {plugin_id} 模块声明出错：{str(err)}")
            return
        manager = ModuleManager()
        for declaration in declarations:
            try:
                manager.register_module(declaration, owner=plugin_id)
            except Exception as err:
                logger.error(f"注册插件 {plugin_id} 的模块出错：{str(err)}")

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
            plugins = dict(self._running_plugins)
        for key, plugin in plugins.items():
            eventmanager.disable_event_handler(type(plugin), key)
            # 先摘除该实例注册的系统模块，避免实例停止后其模块仍留在分发面上
            self._unregister_plugin_modules(key)
            self._stop_plugin(plugin)
        # 清空对象
        if targets is not None:
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



    def on_config_changed(self):
        """在插件监控配置变化后重建文件监控。"""
        self.reload_monitor()

    def get_reload_name(self) -> str:
        """返回配置重载日志使用的功能名称。"""
        return "插件文件修改监测"



    async def async_run_plugin_method(self, pid: str, method: str, *args, **kwargs) -> Any:
        """
        异步运行插件方法
        :param pid: 插件ID
        :param method: 方法名
        :param args: 参数
        :param kwargs: 关键字参数
        """
        plugin = self._running_plugins.get(pid)
        if not plugin:
            return None
        if not hasattr(plugin, method):
            return None
        method_func = getattr(plugin, method)
        if asyncio.iscoroutinefunction(method_func):
            return await method_func(*args, **kwargs)
        else:
            return method_func(*args, **kwargs)

