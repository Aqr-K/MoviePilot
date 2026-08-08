import ast
import asyncio
import concurrent
import concurrent.futures
import dataclasses
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
from app.core.auth_level import get_auth_level
from app.core.cache import fresh, async_fresh
from app.core.config import settings
from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.core.plugin_reporter import report_plugin_install
from app.core.plugin_source import get_plugin_source
from app.helper import plugin_market, plugin_metadata
from app.db.plugindata_oper import PluginDataOper
from app.db.systemconfig_oper import SystemConfigOper
from app.helper.plugin import VERSION_BACKWARD_COMPATIBLE_FLAGS
from app.log import logger
from app.schemas.types import EventType, SystemConfigKey
from app.utils.crypto import RSAUtils
from app.utils.mixins import ConfigReloadMixin
from app.utils.object import ObjectUtils
from app.utils.plugin_repo import is_local_repo_url, make_local_repo_url
from app.utils.singleton import Singleton
from app.utils.string import StringUtils
from app.utils.system import SystemUtils


class PluginManager(ConfigReloadMixin, metaclass=Singleton):
    """插件管理器"""
    CONFIG_WATCH = {"DEV", "PLUGIN_AUTO_RELOAD", "PLUGIN_LOCAL_REPO_PATHS"}
    AGENT_TOOLS_BUILD_MAX_ATTEMPTS = 3

    def __init__(self):
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
        # 保护 _plugins / _running_plugins 的可重入锁：热重载监控线程与请求线程会并发读写这两张表，
        # 写入与遍历读取均须持锁，避免“dictionary changed size during iteration”及读到半更新态。
        self._plugins_lock = threading.RLock()
        # 开发者模式监测插件修改
        if settings.DEV or settings.PLUGIN_AUTO_RELOAD:
            self.__start_monitor()

    def init_config(self):
        # 停止已有插件
        self.stop()
        # 启动插件
        self.start()

    def start(self, pid: Optional[str] = None):
        """
        启动加载插件
        :param pid: 插件ID，为空加载所有插件
        """

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
            try:
                # 判断插件是否满足认证要求，如不满足则不进行实例化
                if not self.__set_and_check_auth_level(plugin=plugin):
                    # 如果是插件热更新实例，这里则进行替换（check-then-act 须在锁内原子完成，
                    # 否则与并发 stop() 存在 TOCTOU：检查与替换之间被摘除会复活已下线插件）
                    with self._plugins_lock:
                        if plugin_id in self._plugins:
                            self._plugins = {**self._plugins, plugin_id: plugin}
                    continue
                # 存储Class（整体替换式写入：并发读侧遍历的是替换前的完整字典，无需读侧加锁）
                with self._plugins_lock:
                    self._plugins = {**self._plugins, plugin_id: plugin}
                # 生成实例
                plugin_obj = plugin()
                # 生效插件配置
                plugin_obj.init_plugin(self.get_plugin_config(plugin_id))
                # 存储运行实例（整体替换式写入）
                with self._plugins_lock:
                    self._running_plugins = {**self._running_plugins, plugin_id: plugin_obj}
                logger.info(f"加载插件：{plugin_id} 版本：{plugin_obj.plugin_version}")
                # 启用的插件才设置事件注册状态可用
                if plugin_obj.get_state():
                    eventmanager.enable_event_handler(plugin)
                else:
                    eventmanager.disable_event_handler(plugin)
            except Exception as err:
                logger.error(f"加载插件 {plugin_id} 出错：{str(err)} - {traceback.format_exc()}")
        # 注册插件经 provides_modules 声明新增的系统模块到模块层（运行期动态上线）
        self._register_plugin_modules(pid)
        # 清空插件智能体工具注册表缓存（上游 2.13.12）
        self.clear_plugin_agent_tools_cache()

    def init_plugin(self, plugin_id: str, conf: dict):
        """
        初始化插件
        :param plugin_id: 插件ID
        :param conf: 插件配置
        """
        plugin = self._running_plugins.get(plugin_id)
        if not plugin:
            return
        # 初始化插件
        plugin.init_plugin(conf)
        # 为声明了 provides_models 的插件创建其自管理的独立数据库表（失败不影响插件其它功能）
        try:
            from app.db.plugin import setup_plugin_database
            setup_plugin_database(plugin)
        except Exception as err:
            logger.error(f"初始化插件 {plugin_id} 自管理数据库出错：{str(err)}")
        # 检查插件状态并启用/禁用事件处理器
        if plugin.get_state():
            # 启用插件类的事件处理器
            eventmanager.enable_event_handler(type(plugin))
        else:
            # 禁用插件类的事件处理器
            eventmanager.disable_event_handler(type(plugin))
        # 运行期重同步该插件注册到模块层的系统模块（启用/禁用/配置变更后幂等上下线）
        self._unregister_plugin_modules([plugin_id])
        self._register_plugin_modules(plugin_id)
        # 清空插件智能体工具注册表缓存（上游 2.13.12）
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

    def stop(self, pid: Optional[str] = None):
        """
        停止插件服务
        :param pid: 插件ID，为空停止所有插件
        """
        # 停止插件
        if pid:
            logger.info(f"正在停止插件 {pid}...")
            plugin_obj = self._running_plugins.get(pid)
            if not plugin_obj:
                # 指定插件可能在上次加载时已导入模块但初始化失败，此时不会进入运行态列表。
                # 仍需继续清理类缓存和 sys.modules，避免后续热重载反复复用旧模块。
                logger.debug(f"插件 {pid} 不存在或未加载")
                plugins = {}
            else:
                plugins = {pid: plugin_obj}
        else:
            logger.info("正在停止所有插件...")
            # 锁内快照后遍历，避免与热重载并发写竞争
            plugins = self._running_snapshot()
        for plugin_id, plugin in plugins.items():
            eventmanager.disable_event_handler(type(plugin))
            self.__stop_plugin(plugin)
        # 卸载这些插件注册到模块层的系统模块（运行期动态下线，无僵尸）。
        # 即便指定插件未进入运行态，也按 owner=pid 兜底卸载其可能残留的模块。
        stopped_ids = list(plugins.keys())
        if pid and pid not in stopped_ids:
            stopped_ids.append(pid)
        self._unregister_plugin_modules(stopped_ids)
        # 清空对象
        if pid:
            # 清空指定插件（整体替换式写入，读侧免锁遍历安全）
            with self._plugins_lock:
                self._plugins = {k: v for k, v in self._plugins.items() if k != pid}
                self._running_plugins = {k: v for k, v in self._running_plugins.items() if k != pid}
            # 清除插件模块缓存，包括所有子模块
            self._clear_plugin_modules(pid)
        else:
            # 清空
            with self._plugins_lock:
                self._plugins = {}
                self._running_plugins = {}
            # 清除所有插件模块缓存
            self._clear_plugin_modules()
        self.clear_plugin_agent_tools_cache()
        logger.info("插件停止完成")

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

    def _running_snapshot(self) -> Dict[str, Any]:
        """
        运行态插件字典的锁内浅拷贝快照，供需遍历的只读路径使用，避免与热重载并发写竞争。
        :return: {plugin_id: 运行实例} 的浅拷贝
        """
        with self._plugins_lock:
            return dict(self._running_plugins)

    def _plugins_snapshot(self) -> Dict[str, Any]:
        """
        插件类字典的锁内浅拷贝快照，供需遍历的只读路径使用，避免与热重载并发写竞争。
        :return: {plugin_id: 插件类} 的浅拷贝
        """
        with self._plugins_lock:
            return dict(self._plugins)

    @property
    def running_plugins(self) -> Dict[str, Any]:
        """
        获取运行态插件列表
        :return: 运行态插件列表

        注意：返回内部字典的实时引用（既有调用方依赖对其直接 .get()/.pop() 操作），
        需遍历且要求线程安全的内部路径请改用 _running_snapshot()。
        """
        return self._running_plugins

    @property
    def plugins(self) -> Dict[str, Any]:
        """
        获取插件列表
        :return: 插件列表

        注意：返回内部字典的实时引用（既有调用方依赖对其直接 .get()/.pop() 操作），
        需遍历且要求线程安全的内部路径请改用 _plugins_snapshot()。
        """
        return self._plugins

    def on_config_changed(self):
        self.reload_monitor()

    def get_reload_name(self) -> str:
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
        for local_repo_path in get_plugin_source().get_local_repo_paths():
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
                self._collect_watch_change(Path(path_str), plugins_to_reload, local_plugins_to_sync)

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

    def _collect_watch_change(self, event_path: Path, plugins_to_reload: set,
                              local_plugins_to_sync: dict) -> None:
        """
        归类单个文件变化事件，按需登记重载或本地同步目标。

        :param event_path: 变化的文件路径
        :param plugins_to_reload: 待重载插件 id 集合（原地累加）
        :param local_plugins_to_sync: 待同步本地插件 {id: (candidate, path, should_reload)}（原地累加）
        :return: 无
        """
        # 跳过 pycache 目录中的文件
        if "__pycache__" in event_path.parts:
            return

        # 依赖文件变化：仅提示，不触发重载/同步
        if event_path.name == "requirements.txt":
            candidate = self._get_local_plugin_candidate_from_path(event_path)
            if not candidate:
                return
            if candidate.get("compatible") is False:
                logger.info(
                    f"检测到本地插件 {candidate.get('id')} 依赖文件变化，"
                    f"但跳过处理：{candidate.get('skip_reason')}"
                )
                return
            logger.warn(f"检测到本地插件 {candidate.get('id')} 依赖文件变化，请重新安装本地插件以安装依赖")
            return

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
            return

        # 跳过非 .py 文件
        if not event_path.name.endswith(".py"):
            return

        # 运行目录变化：只重载，不能反向触发本地同步
        runtime_pid = self._get_plugin_id_from_path(event_path)
        if runtime_pid:
            last_sync_time = self._recent_local_sync.get(runtime_pid)
            if last_sync_time and time.time() - last_sync_time < 2:
                return
            plugins_to_reload.add(runtime_pid)
            return

        # 本地插件源变化：登记待同步
        local_candidate = self._get_local_plugin_candidate_from_path(event_path)
        if not local_candidate:
            return
        if local_candidate.get("compatible") is False:
            package_version = local_candidate.get("package_version")
            source_root = f"plugins.{package_version}" if package_version else "plugins"
            logger.info(
                f"检测到本地插件 {local_candidate.get('id')} 文件变化，来源：{source_root}，"
                f"文件：{event_path}，但跳过同步：{local_candidate.get('skip_reason')}"
            )
            return
        local_plugins_to_sync[local_candidate.get("id")] = (local_candidate, event_path, True)

    def _get_federated_plugin_change(
        self,
        event_path: Path,
    ) -> Optional[Tuple[str, Optional[dict], bool]]:
        """
        识别运行态 Vue 插件声明目录内的构建产物变化。

        :param event_path: 变化的文件路径
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
                        plugin_id
                        for plugin_id in self._running_plugins
                        if plugin_id.lower() == relative_parts[0].lower()
                    ),
                    None,
                )

            if not pid:
                return None
            plugin = self._running_plugins.get(pid)
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
            for local_repo_path in get_plugin_source().get_local_repo_paths():
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
                candidate = get_plugin_source().get_local_plugin_candidate(
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

        candidate = candidate or get_plugin_source().get_local_plugin_candidate(pid)
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

    def remove_plugin_class(self, plugin_id: str) -> None:
        """
        从插件类表中移除指定插件（整体替换式写入，锁内完成）。

        供卸载分身等需在 stop() 之外单独摘除类引用的场景使用，替代对 plugins 属性的就地 .pop()，
        与 start()/stop() 的整体替换写入保持一致，确保并发读侧遍历安全。
        :param plugin_id: 插件ID
        """
        with self._plugins_lock:
            self._plugins = {k: v for k, v in self._plugins.items() if k != plugin_id}

    def remove_plugin(self, plugin_id: str):
        """
        从内存中移除一个插件
        :param plugin_id: 插件ID
        """
        self.stop(plugin_id)
        # 释放该插件自管理数据库的连接（仅释放连接、保留数据；删库只在明确删除数据时进行）
        try:
            from app.db.manager import db_manager
            db_manager.dispose(plugin_id)
        except Exception as err:
            logger.error(f"释放插件 {plugin_id} 自管理数据库连接出错：{str(err)}")

    def reload_plugin(self, plugin_id: str):
        """
        将一个插件重新加载到内存，并内聚地重建其调度服务、菜单命令与 API 路由。

        热重载须先下线（stop 内含模块/事件处理器下线）、再上线（start 内含模块/事件处理器上线），
        随后同步重建调度/命令/路由绑定——否则文件监控、插件分身等“直接调用 reload_plugin”的路径
        会残留指向旧实例的过期定时任务/命令/路由（仅 API、agent 工具两条路径先前在外层补刷）。
        register_plugin 为幂等（先摘后建/replace_existing），与外层可能的重复调用叠加亦安全。
        :param plugin_id: 插件ID
        """
        # 先移除插件实例（含模块、事件处理器下线）
        self.stop(plugin_id)
        # 重新加载（含模块、事件处理器上线）
        self.start(plugin_id)
        # 同步重建调度服务/菜单命令/API 路由（惰性导入，避免 helper 顶层产生对 api/调度/命令层的依赖边）
        try:
            from app.api.endpoints.plugin import register_plugin
            register_plugin(plugin_id)
            # 绑定就绪后再广播事件，避免在同步绑定失败后仍发出"已重载"信号
            eventmanager.send_event(EventType.PluginReload, data={"plugin_id": plugin_id})
        except Exception as err:
            logger.error(f"重载插件 {plugin_id} 同步调度/命令/API 绑定出错：{str(err)}")

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

    def _register_plugin_modules(self, pid: Optional[str] = None):
        """
        将运行态插件经 provides_modules() 声明的系统模块注册到 ModuleManager（owner=plugin_id），
        随即进入 chain 分发。仅注册已启用插件（聚合器按 get_state 过滤）。pid 为空时处理全部插件。
        """
        provided = plugin_metadata.get_plugin_provided_modules(self._running_plugins, pid)
        for plugin_id, module_classes in provided.items():
            for module_cls in module_classes:
                try:
                    ModuleManager().register_module(module_cls, owner=plugin_id)
                except Exception as err:
                    logger.error(f"注册插件 {plugin_id} 模块 "
                                 f"{getattr(module_cls, '__name__', module_cls)} 出错：{str(err)}")
        # 注册插件经 provides_storages 声明新增的存储器到文件整理层
        provided_storages = plugin_metadata.get_plugin_provided_storages(self._running_plugins, pid)
        if provided_storages:
            from app.modules.filemanager import FileManagerModule
            for plugin_id, storage_classes in provided_storages.items():
                for storage_cls in storage_classes:
                    try:
                        FileManagerModule.register_storage(storage_cls, owner=plugin_id)
                    except Exception as err:
                        logger.error(f"注册插件 {plugin_id} 存储器 "
                                     f"{getattr(storage_cls, '__name__', storage_cls)} 出错：{str(err)}")
        # 注册插件经 provides_auth_* 声明的认证域实例（登录提供方 / 认证流程 / 认证步骤）：
        # 不进 ModuleManager/chain，而是注册到 app.core.auth 各注册表（owner=plugin_id），由认证流程统一驱动。
        # auth 域注册整体隔离：import 或注册失败仅记录日志，不得波及后续契约域/通知域注册
        # （与 _unregister_plugin_modules 的逐项 try 对称，避免单域故障放大为全插件注册失败）。
        try:
            from app.core.auth.flow_registry import register_auth_flow
            from app.core.auth.redirect import register_auth_provider
            from app.core.auth.steps import register_auth_step
            for _get_provided, _register, _id_attr, _label in (
                (plugin_metadata.get_plugin_provided_auth_providers, register_auth_provider, "provider_id", "登录提供方"),
                (plugin_metadata.get_plugin_provided_auth_flows, register_auth_flow, "flow_id", "认证流程"),
                (plugin_metadata.get_plugin_provided_auth_steps, register_auth_step, "step_id", "认证步骤"),
            ):
                self._register_auth_domain(pid, _get_provided, _register, _id_attr, _label)
        except Exception as err:
            logger.error(f"注册插件 {pid} 认证域出错（不影响其它域）：{str(err)}")
        # 注册插件经 provides_* 声明新增的各契约域模块（数据源/下载器/媒体服务器）：
        # 经各自契约校验通过后注册到 ModuleManager（owner=plugin_id），参与 chain 分发。
        for _get_provided, _verify, _label in (
            (plugin_metadata.get_plugin_provided_data_sources, ModuleManager.verify_data_source_contract, "数据源"),
            (plugin_metadata.get_plugin_provided_downloaders, ModuleManager.verify_downloader_contract, "下载器"),
            (plugin_metadata.get_plugin_provided_mediaservers, ModuleManager.verify_mediaserver_contract, "媒体服务器"),
        ):
            self._register_contract_domain(pid, _get_provided, _verify, _label)
        # 注册插件经 provides_notifications 声明【新增】的消息渠道（Notification 域）：经契约校验注册模块外，
        # 渠道模块自带的 get_channel_capabilities() 能力矩阵随注册一并登记（能力声明收口于渠道模块）。
        self._register_notification_domain(pid)

    def _register_contract_domain(self, pid, get_provided, verify_contract, label: str):
        """
        注册某契约域插件类的共用实现（数据源/下载器/媒体服务器）：聚合插件声明的类 →
        经域契约校验（不通过仅警告拒绝、不影响其它）→ register_module(owner=plugin_id)。
        消息渠道（Notification 域）另经 _register_notification_domain 处理（需附带能力矩阵登记）。
        """
        for plugin_id, classes in get_provided(self._running_plugins, pid).items():
            for cls in classes:
                _name = getattr(cls, "__name__", cls)
                ok, reasons = verify_contract(cls)
                if not ok:
                    logger.warning(f"插件 {plugin_id} {label} {_name} 未通过{label}契约校验，拒绝注册："
                                   f"{'；'.join(reasons)}")
                    continue
                try:
                    ModuleManager().register_module(cls, owner=plugin_id)
                except Exception as err:
                    logger.error(f"注册插件 {plugin_id} {label} {_name} 出错：{str(err)}")

    def _register_notification_domain(self, pid: Optional[str] = None) -> None:
        """
        注册插件经 provides_notifications 声明【新增】的消息渠道（Notification 域）：聚合插件声明的类 →
        经消息渠道契约校验（不通过仅警告拒绝、不影响其它）→ register_module(owner=plugin_id) 进 chain 分发 →
        读取渠道模块运行实例自带的 get_channel_capabilities() 能力矩阵一并登记到 ChannelCapabilityManager
        （能力声明随渠道模块一处声明）。
        """
        for plugin_id, classes in plugin_metadata.get_plugin_provided_notifications(self._running_plugins, pid).items():
            for cls in classes:
                _name = getattr(cls, "__name__", cls)
                ok, reasons = ModuleManager.verify_notification_contract(cls)
                if not ok:
                    logger.warning(f"插件 {plugin_id} 消息渠道 {_name} 未通过消息渠道契约校验，拒绝注册："
                                   f"{'；'.join(reasons)}")
                    continue
                try:
                    if not ModuleManager().register_module(cls, owner=plugin_id):
                        logger.debug(f"插件 {plugin_id} 消息渠道 {_name} register_module 未激活，跳过能力矩阵登记")
                        continue
                except Exception as err:
                    logger.error(f"注册插件 {plugin_id} 消息渠道 {_name} 出错：{str(err)}")
                    continue
                self._register_channel_capabilities(plugin_id, cls)

    @staticmethod
    def _register_channel_capabilities(plugin_id: str, module_cls: type) -> None:
        """
        从已注册的消息渠道模块运行实例读取其自带 get_channel_capabilities() 能力矩阵，按 get_subtype_id()
        的 channel id 登记到 ChannelCapabilityManager（owner=plugin_id）。模块未声明能力则跳过，走降级默认。
        channel id 仅在模块 get_subtype_id() 一处声明，能力矩阵的 channel 字段以此为准盖章，避免两处对齐。
        """
        instance = ModuleManager().get_running_module(getattr(module_cls, "__name__", ""))
        getter = getattr(instance, "get_channel_capabilities", None)
        if not callable(getter):
            logger.debug(f"插件 {plugin_id} 消息渠道 {getattr(module_cls, '__name__', module_cls)} "
                         f"未提供 get_channel_capabilities，跳过能力登记（走降级默认）")
            return
        try:
            caps = getter()
            if caps is None:
                return
            channel_id = instance.get_subtype_id()
            if not channel_id:
                return
            from app.schemas.message import ChannelCapabilityManager
            ChannelCapabilityManager.register_capabilities(
                channel_id, dataclasses.replace(caps, channel=channel_id), owner=plugin_id)
        except Exception as err:
            logger.error(f"注册插件 {plugin_id} 渠道能力出错：{str(err)}")

    def _register_auth_domain(self, pid, get_provided, register_fn, id_attr: str, label: str) -> None:
        """
        注册某认证域插件实例的共用实现（登录提供方 / 认证流程 / 认证步骤）：聚合插件声明的实例 →
        经 register_fn 注册到对应核心注册表（owner=plugin_id）→ 失败仅警告、不影响其它。

        :param pid: 目标插件 id；None 表示全部运行中插件
        :param get_provided: plugin_metadata 中对应的聚合函数
        :param register_fn: 核心注册表的注册函数，签名 (item, owner) -> (ok, reason)
        :param id_attr: 用于日志的实例标识属性名（provider_id / flow_id / step_id）
        :param label: 中文域名（用于日志）
        :return: 无
        """
        for plugin_id, items in get_provided(self._running_plugins, pid).items():
            for item in items:
                ok, reason = register_fn(item, owner=plugin_id)
                if not ok:
                    logger.warning(f"注册插件 {plugin_id} {label} {getattr(item, id_attr, item)} 失败：{reason}")

    def _unregister_plugin_modules(self, plugin_ids: List[str]):
        """
        卸载指定插件注册到 ModuleManager 的系统模块，停止其运行实例，无僵尸残留。
        """
        from app.modules.filemanager import FileManagerModule
        from app.schemas.message import ChannelCapabilityManager
        for plugin_id in plugin_ids:
            try:
                ModuleManager().unregister_modules(owner=plugin_id)
            except Exception as err:
                logger.error(f"卸载插件 {plugin_id} 模块出错：{str(err)}")
            try:
                FileManagerModule.unregister_storages(owner=plugin_id)
            except Exception as err:
                logger.error(f"卸载插件 {plugin_id} 存储器出错：{str(err)}")
            try:
                ChannelCapabilityManager.unregister_capabilities(owner=plugin_id)
            except Exception as err:
                logger.error(f"卸载插件 {plugin_id} 渠道能力出错：{str(err)}")
            try:
                from app.core.auth.redirect import unregister_auth_providers
                unregister_auth_providers(owner=plugin_id)
            except Exception as err:
                logger.error(f"卸载插件 {plugin_id} 登录提供方出错：{str(err)}")
            try:
                from app.core.auth.flow_registry import unregister_auth_flows
                from app.core.auth.steps import unregister_auth_steps
                unregister_auth_flows(owner=plugin_id)
                unregister_auth_steps(owner=plugin_id)
            except Exception as err:
                logger.error(f"卸载插件 {plugin_id} 认证组件出错：{str(err)}")

    def sync(self) -> List[str]:
        """
        安装本地不存在或需要更新的插件
        """

        def install_plugin(plugin):
            start_time = time.time()
            state, msg = get_plugin_source().install(pid=plugin.id, repo_url=plugin.repo_url, force_install=True)
            elapsed_time = time.time() - start_time
            if state:
                report_plugin_install(plugin_id=plugin.id, repo_url=plugin.repo_url)
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
        return plugin_market.install_plugin_missing_dependencies()

    def get_plugin_config(self, pid: str) -> dict:
        """
        获取插件配置
        :param pid: 插件ID
        """
        if not self._plugins.get(pid):
            return {}
        conf = SystemConfigOper().get(self._config_key % pid)
        if conf:
            # 去掉空Key
            return {k: v for k, v in conf.items() if k}
        return {}

    def save_plugin_config(self, pid: str, conf: dict, force: bool = False) -> bool:
        """
        保存插件配置
        :param pid: 插件ID
        :param conf: 配置
        :param force: 强制保存
        """
        if not force and not self._plugins.get(pid):
            return False
        SystemConfigOper().set(self._config_key % pid, conf)
        return True

    async def async_save_plugin_config(
        self, pid: str, conf: dict, force: bool = False
    ) -> bool:
        """
        异步保存插件配置。
        :param pid: 插件ID
        :param conf: 配置
        :param force: 强制保存
        """
        if not force and not self._plugins.get(pid):
            return False
        await SystemConfigOper().async_set(self._config_key % pid, conf)
        return True

    def delete_plugin_config(self, pid: str, force: bool = False) -> bool:
        """
        删除插件配置
        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化配置
        """
        if not force and not self._plugins.get(pid):
            return False
        return SystemConfigOper().delete(self._config_key % pid)

    def delete_plugin_data(self, pid: str, force: bool = False) -> bool:
        """
        删除插件数据
        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化数据
        """
        if not force and not self._plugins.get(pid):
            return False
        PluginDataOper().del_data(pid)
        # 删除插件自管理的独立数据库（释放容器并删除 .db 文件，失败不影响数据清理结果）
        try:
            from app.db.plugin import teardown_plugin_database
            teardown_plugin_database(pid)
        except Exception as err:
            logger.error(f"删除插件 {pid} 自管理数据库出错：{str(err)}")
        return True

    def get_plugin_state(self, pid: str) -> bool:
        """
        获取插件状态
        :param pid: 插件ID
        """
        plugin = self._running_plugins.get(pid)
        return plugin.get_state() if plugin else False

    def get_plugin_commands(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_commands(self._running_plugins, pid)

    def get_plugin_apis(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_apis(self._running_plugins, pid)

    def get_plugin_services(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_services(self._running_plugins, pid)

    def get_plugin_modules(self, pid: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
        return plugin_metadata.get_plugin_modules(self._running_plugins, pid)

    def get_plugin_actions(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_actions(self._running_plugins, pid)

    def get_plugin_provided_discover_sources(self, pid: Optional[str] = None) -> Dict[str, List[Any]]:
        return plugin_metadata.get_plugin_provided_discover_sources(self._running_plugins, pid)

    def get_plugin_provided_recommend_sources(self, pid: Optional[str] = None) -> Dict[str, List[Any]]:
        return plugin_metadata.get_plugin_provided_recommend_sources(self._running_plugins, pid)

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

            # 工具收集逻辑在 app.helper.plugin_metadata，此处仅在其上叠加注册表缓存层
            ret_tools = plugin_metadata.get_plugin_agent_tools(self._running_plugins, pid)
            with self._plugin_agent_tools_cache_lock:
                if cache_revision != self._plugin_agent_tools_revision:
                    # 插件状态在注册表构建期间发生变化，重新读取以避免写回过期快照。
                    continue
                self._plugin_agent_tools_cache[cache_key] = self._copy_plugin_agent_tools(ret_tools)
                return ret_tools
        raise RuntimeError("插件工具注册表持续变化，无法建立当前快照")

    @staticmethod
    def get_plugin_remote_entry(plugin_id: str, dist_path: str) -> str:
        return plugin_metadata.get_plugin_remote_entry(plugin_id, dist_path)

    def get_plugin_remotes(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_remotes(self._running_plugins, pid)

    def get_plugin_auth_providers(self) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_auth_providers(self._running_plugins)

    def get_plugin_sidebar_nav(self) -> List[Dict[str, Any]]:
        return plugin_metadata.get_plugin_sidebar_nav(self._running_plugins)

    def get_plugin_dashboard_meta(self) -> List[Dict[str, str]]:
        return plugin_metadata.get_plugin_dashboard_meta(self._running_plugins)

    def get_plugin_dashboard(self, pid: str, key: str, user_agent: str = None) -> Optional[schemas.PluginDashboard]:
        return plugin_metadata.get_plugin_dashboard(self._running_plugins, pid, key, user_agent)

    def get_plugin_attr(self, pid: str, attr: str) -> Any:
        """
        获取插件属性
        :param pid: 插件ID
        :param attr: 属性名
        """
        plugin = self._running_plugins.get(pid)
        if not plugin:
            return None
        if not hasattr(plugin, attr):
            return None
        return getattr(plugin, attr)

    def run_plugin_method(self, pid: str, method: str, *args, **kwargs) -> Any:
        """
        运行插件方法
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
        return getattr(plugin, method)(*args, **kwargs)

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

    def get_plugin_ids(self) -> List[str]:
        """
        获取所有插件ID
        """
        return list(self._plugins.keys())

    def get_running_plugin_ids(self) -> List[str]:
        """
        获取所有运行态插件ID
        """
        return list(self._running_plugins.keys())

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
        # 锁内快照后遍历，避免与热重载并发写竞争
        for pid, plugin_class in self._plugins_snapshot().items():
            # 运行状插件
            plugin_obj = self._running_plugins.get(pid)
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
        plugin_class = self._plugins.get(pid)
        if not plugin_class:
            return None
        return getattr(plugin_class, "plugin_version", None)

    def get_local_repo_plugins(self) -> List[schemas.Plugin]:
        """
        获取本地插件仓库目录中的插件信息
        """
        plugins = []
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        local_candidates = get_plugin_source().get_local_plugin_candidates()
        if not local_candidates:
            return []
        for pid, plugin_info in local_candidates.items():
            package_version = plugin_info.get("package_version")
            plugin = self._process_plugin_info(
                pid=pid,
                plugin_info=plugin_info,
                market=make_local_repo_url(
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

            if version and not StringUtils.compare_version(local_version, ">=", version):
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
            online_plugins = get_plugin_source().get_plugins(market, package_version)
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
        return plugin_market.process_plugins_list(higher_version_plugins, base_version_plugins)

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

        plugin_info = get_plugin_source().annotate_plugin_system_version(plugin_info.copy())
        if not get_plugin_source().is_package_plugin_compatible(
                plugin_info, package_version or ""
        ):
            # 插件当前版本不兼容
            return None

        # 运行状插件
        plugin_obj = self._running_plugins.get(pid)
        # 非运行态插件
        plugin_static = self._plugins.get(pid)
        # 基本属性
        plugin = schemas.Plugin()
        # ID
        plugin.id = pid
        # 安装状态
        plugin.installed = bool(pid in installed_apps and plugin_static)
        # 是否有新版本
        plugin.has_update = False
        if plugin_static:
            installed_version = getattr(plugin_static, "plugin_version")
            if StringUtils.compare_version(installed_version, "<", plugin_info.get("version")):
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
        plugin.has_page = bool(
            plugin_obj and hasattr(plugin_obj, "get_page")
            and ObjectUtils.check_method(plugin_obj.get_page))
        # 权限
        if not self.__set_and_check_auth_level(plugin=plugin, source=plugin_info):
            return None
        # 市场字段 → Plugin 属性：仅当市场提供真值时覆盖，否则保留 schema 默认值
        for field, attr in (
            ("key", "plugin_public_key"),
            ("name", "plugin_name"),
            ("description", "plugin_desc"),
            ("version", "plugin_version"),
            ("icon", "plugin_icon"),
            ("author", "plugin_author"),
            ("history", "history"),
        ):
            value = plugin_info.get(field)
            if value:
                setattr(plugin, attr, value)
        # 标签
        plugin.plugin_label = self._normalize_plugin_label(plugin_info.get("labels"))
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
            online_plugins = await get_plugin_source().async_get_plugins(market, package_version)
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
        current_auth_level = get_auth_level()
        if current_auth_level > 1 and plugin.auth_level == 99 and hasattr(plugin, "plugin_public_key"):
            plugin_id = plugin.id if isinstance(plugin, schemas.Plugin) else plugin.__name__
            public_key = plugin.plugin_public_key
            if public_key:
                private_key = PluginManager.__get_plugin_private_key(plugin_id)
                verify = RSAUtils.verify_rsa_keys(public_key=public_key, private_key=private_key)
                return verify
        # 如果当前站点认证级别小于插件级别，则返回 False
        if current_auth_level < plugin.auth_level:
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

    def clone_plugin(self, plugin_id: str, suffix: str, name: str, description: str,
                     version: str = None, icon: str = None) -> Tuple[bool, str]:
        """
        创建插件分身
        :param plugin_id: 原插件ID
        :param suffix: 分身后缀
        :param name: 分身名称
        :param description: 分身描述
        :param version: 自定义版本号
        :param icon: 自定义图标URL
        :return: (是否成功, 错误信息)
        """
        try:
            # 验证参数
            if not plugin_id or not suffix:
                return False, "插件ID和分身后缀不能为空"

            # 分身后缀白名单：后缀会拼进目录名与生成代码的类名，必须限定为 ASCII 字母数字，
            # 否则可造成目录穿越（../）或注入 __init__.py 生成代码。
            if not (1 <= len(suffix) <= 20 and suffix.isascii() and suffix.isalnum()):
                return False, "分身后缀仅允许 1-20 位字母或数字"

            # 检查原插件是否存在
            if plugin_id not in self._plugins:
                return False, f"原插件 {plugin_id} 不存在"

            # 生成分身插件ID
            clone_id = f"{plugin_id}{suffix.lower()}"

            # 检查分身插件是否已存在
            if self.is_plugin_exists(clone_id):
                return False, f"分身插件 {clone_id} 已存在"

            # 获取原插件目录
            original_plugin_dir = Path(settings.ROOT_PATH) / "app" / "plugins" / plugin_id.lower()
            if not original_plugin_dir.exists():
                return False, f"原插件目录 {original_plugin_dir} 不存在"

            # 创建分身插件目录
            clone_plugin_dir = Path(settings.ROOT_PATH) / "app" / "plugins" / clone_id.lower()

            # 目录穿越守卫（防御纵深）：分身目录必须落在 plugins 根目录内
            plugins_root = Path(settings.ROOT_PATH) / "app" / "plugins"
            if not SystemUtils.is_within(plugins_root, clone_plugin_dir):
                return False, "分身插件目录非法（越界）"

            # 复制插件目录
            import shutil
            shutil.copytree(original_plugin_dir, clone_plugin_dir)
            logger.info(f"已复制插件目录：{original_plugin_dir} -> {clone_plugin_dir}")

            # 解析原插件类名（实例状态 _plugins 读取保留在 PluginManager）
            original_plugin_class = self._plugins.get(plugin_id)
            if not original_plugin_class:
                if clone_plugin_dir.exists():
                    shutil.rmtree(clone_plugin_dir)
                return False, f"无法获取原插件类 {plugin_id}"
            original_class_name = original_plugin_class.__name__
            clone_class_name = f"{original_class_name}{suffix.lower()}"

            # 修改插件文件内容（纯文件/AST 改写已抽至 app.helper.plugin_cloner，S9b）
            from app.helper import plugin_cloner
            success, msg = plugin_cloner.modify_plugin_files(
                plugin_dir=clone_plugin_dir,
                original_class_name=original_class_name,
                clone_class_name=clone_class_name,
                name=name,
                description=description,
                version=version,
                icon=icon
            )

            if not success:
                # 如果修改失败，清理已创建的目录
                if clone_plugin_dir.exists():
                    shutil.rmtree(clone_plugin_dir)
                return False, msg

            # 将分身插件添加到已安装列表
            systemconfig = SystemConfigOper()
            installed_plugins = systemconfig.get(SystemConfigKey.UserInstalledPlugins) or []
            if clone_id not in installed_plugins:
                installed_plugins.append(clone_id)
                systemconfig.set(SystemConfigKey.UserInstalledPlugins, installed_plugins)

            # 为分身插件创建初始配置（从原插件复制配置）
            logger.info(f"正在为分身插件 {clone_id} 创建初始配置...")
            original_config = self.get_plugin_config(plugin_id)
            if original_config:
                # 复制原插件配置作为分身插件的初始配置
                clone_config = original_config.copy()
                # 可以在这里修改一些默认值，比如禁用分身插件
                # 默认禁用分身插件，让用户手动配置
                clone_config['enable'] = False
                clone_config['enabled'] = False
                self.save_plugin_config(clone_id, clone_config, force=True)
                logger.info(f"已为分身插件 {clone_id} 设置初始配置")
            else:
                logger.info(f"原插件 {plugin_id} 没有配置，分身插件 {clone_id} 将使用默认配置")

            # 注册分身插件的API和服务
            logger.info(f"正在注册分身插件 {clone_id} ...")
            PluginManager().reload_plugin(clone_id)
            # 确保分身插件正确初始化配置
            if clone_id in self._running_plugins:
                clone_instance = self._running_plugins[clone_id]
                clone_config = self.get_plugin_config(clone_id)
                if clone_config:
                    logger.info(f"正在为分身插件 {clone_id} 重新初始化配置...")
                    clone_instance.init_plugin(clone_config)
                    logger.info(f"分身插件 {clone_id} 配置重新初始化完成")

            logger.info(f"插件分身 {clone_id} 创建成功")
            return True, clone_id

        except Exception as e:
            logger.error(f"创建插件分身失败：{str(e)}")
            return False, f"创建插件分身失败：{str(e)}"
