"""插件管理器。

各功能域按 mixin 分文件，本模块保留插件注册表本身与其生命周期，并对外维持与拆分前
一致的导入面。共享依赖与可注入服务集中在 ``_shared``，各域单向依赖它。
"""
import asyncio
import threading
import traceback
from typing import Any, Dict, List, Optional, Type

from app.foundation.singleton import Singleton
from app.runtime.events import EventHandlerBinding, eventmanager
from app.runtime.log import logger
from app.runtime.reload import ConfigReloadMixin
from app.schemas.types import SystemConfigKey

from app.runtime.extensions import plugin_shared as _shared
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
from app.runtime.extensions.plugin_manager._clone import _PluginCloneMixin

__all__ = [
    "PluginManager",
    "configure_plugin_install_reporter",
    "configure_plugin_legacy_import_services",
    "configure_plugin_resource_import_preparer",
    "configure_site_auth_level_provider",
]


class PluginManager(
    _PluginLoaderMixin,
    _PluginWatcherMixin,
    _PluginConfigMixin,
    _PluginCapabilityMixin,
    _PluginUIMixin,
    _PluginCatalogMixin,
    _PluginCloneMixin,
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
            self.resolve_event_handler_instance,
        )
        # 开发者模式监测插件修改
        if _shared.settings.DEV or _shared.settings.PLUGIN_AUTO_RELOAD:
            self._start_monitor()

    def resolve_event_handler_instance(
            self,
            owner_class: Type[Any],
    ) -> Optional[EventHandlerBinding]:
        """为插件声明的事件方法解析当前运行实例。"""
        plugin_id = owner_class.__name__
        if plugin_id not in self._plugins:
            return None
        plugin = self._running_plugins.get(plugin_id)
        owner_name = plugin_id
        if plugin and callable(getattr(plugin, "get_name", None)):
            owner_name = plugin.get_name()
        return EventHandlerBinding(
            instance=plugin,
            owner_name=owner_name,
            run_sync_in_threadpool=True,
        )

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
            try:
                # 判断插件是否满足认证要求，如不满足则不进行实例化
                if not self._set_and_check_auth_level(plugin=plugin):
                    # 如果是插件热更新实例，这里则进行替换
                    if plugin_id in self._plugins:
                        self._plugins[plugin_id] = plugin
                    continue
                # 存储Class
                self._plugins[plugin_id] = plugin
                # 生成实例
                plugin_obj = plugin()
                # 生效插件配置
                plugin_obj.init_plugin(self.get_plugin_config(plugin_id))
                # 存储运行实例
                self._running_plugins[plugin_id] = plugin_obj
                logger.info(f"加载插件：{plugin_id} 版本：{plugin_obj.plugin_version}")
                # 启用的插件才设置事件注册状态可用
                if plugin_obj.get_state():
                    eventmanager.enable_event_handler(plugin)
                else:
                    eventmanager.disable_event_handler(plugin)
                self._sync_plugin_modules(plugin_id, plugin_obj)
            except Exception as err:
                logger.error(f"加载插件 {plugin_id} 出错：{str(err)} - {traceback.format_exc()}")
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
        # 为声明了 provides_models 的插件建立其自管理的表，失败不影响插件其它功能
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
        # 配置变更可能改变插件启停状态与模块声明，按当前声明重新同步
        self._sync_plugin_modules(plugin_id, plugin)
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
            plugins = self._running_plugins
        for plugin_id, plugin in plugins.items():
            eventmanager.disable_event_handler(type(plugin))
            # 先摘除该插件注册的系统模块，避免插件停止后其模块仍留在分发面上
            self._unregister_plugin_modules(plugin_id)
            self._stop_plugin(plugin)
        # 清空对象
        if pid:
            # 清空指定插件
            self._plugins.pop(pid, None)
            self._running_plugins.pop(pid, None)
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

    def get_running_plugin_ids(self) -> List[str]:
        """
        获取所有运行态插件ID
        """
        return list(self._running_plugins.keys())
