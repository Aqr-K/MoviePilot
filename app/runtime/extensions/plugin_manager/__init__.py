"""插件管理器。

持有插件类表与运行态实例表，负责插件的装载、卸载与扩展点编排，并把外部协作者（数据库
操作对象、模块管理器、事件总线、认证校验）收敛在这一层；注册表查询、实例增删、配置读写
与清单装配由各能力模块提供，它们只依赖传入的注册表与包外符号。
"""
import traceback
from typing import Any, List, Optional, Type

from app import schemas
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.systemconfig import SystemConfigOper
from app.foundation.singleton import Singleton
from app.runtime.config import settings
from app.runtime.events import eventmanager
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_auth import set_and_check_auth_level
from app.runtime.extensions.plugin_instance import instance_key
from app.runtime.extensions.plugin_lifecycle import (
    extension_owners,
    reclaim_extension_owners,
    register_plugin_extensions,
    register_plugin_modules,
    unregister_capability_owners,
    unregister_module_owners,
)
from app.runtime.extensions.plugin_loader import (
    apply_legacy_import_diagnostics,
    clear_plugin_modules,
    load_selective_plugins,
)
from app.runtime.extensions.plugin_manager.catalog import apply_plugin_metadata, build_plugin_summary
from app.runtime.extensions.plugin_manager.configs import PluginConfigMixin
from app.runtime.extensions.plugin_manager.instances import PluginInstanceMixin
from app.runtime.extensions.plugin_manager.registry import PluginRegistryMixin
from app.runtime.extensions.plugin_spi import clear_plugin_agent_tools_cache
from app.runtime.log import logger
from app.schemas.types import EventType, SystemConfigKey


class PluginManager(PluginRegistryMixin, PluginInstanceMixin, PluginConfigMixin,
                    metaclass=Singleton):
    """插件管理器"""

    def __init__(self):
        """初始化插件注册表并接管插件实例的事件解析。"""
        # 插件列表，键为实例键，值为插件类；同一个类会被该插件的全部实例键指向
        self._plugins: dict = {}
        # 运行态插件列表，键为实例键，值为插件实例
        self._running_plugins: dict = {}
        # 事件总线只通过通用解析器访问运行中的插件实例。
        eventmanager.register_handler_instance_resolver(
            "plugins",
            self.resolve_event_handler_instances,
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

        apply_legacy_import_diagnostics(
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
        plugins = load_selective_plugins(pid, installed_plugins, check_module)
        # 排序
        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        for plugin in plugins:
            plugin_id = plugin.__name__
            if pid and plugin_id != pid:
                continue
            # 判断插件是否满足认证要求，如不满足则不进行实例化
            if not set_and_check_auth_level(plugin=plugin):
                # 如果是插件热更新实例，这里则进行替换
                for key in self.get_instance_keys(plugin_id):
                    self._plugins[key] = plugin
                continue
            # 逐个拉起该插件已配置的实例
            for instance_id in self._list_instance_ids(plugin_id):
                self._start_instance(plugin, plugin_id, instance_id)
        self._register_plugin_extensions(pid)
        clear_plugin_agent_tools_cache()

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
        if not set_and_check_auth_level(plugin=plugin_class):
            logger.warning(f"插件 {plugin_id} 不满足认证要求，实例 {normalized} 不拉起")
            return False
        started = self._start_instance(plugin_class, plugin_id, normalized)
        key = instance_key(plugin_id, normalized)
        # 扩展点按实例键注册，兄弟实例的既有注册不受影响
        self._register_plugin_extensions(key)
        clear_plugin_agent_tools_cache()
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
            logger.error(f"初始化插件 {plugin_id} 自管理数据库出错：{str(err)}")
        # 插件启停和配置变更都可能改变声明，先回收再按最新声明注册；
        # 排在自管理表建立之后，使模块初始化能用上插件自己的表
        self._unregister_extension_owners([key])
        self._register_plugin_extensions(key)
        # 检查插件实例状态并启用/禁用事件处理器
        if plugin.get_state():
            # 启用该实例的事件处理器
            eventmanager.enable_event_handler(type(plugin), key)
        else:
            # 禁用该实例的事件处理器
            eventmanager.disable_event_handler(type(plugin), key)
        clear_plugin_agent_tools_cache()

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
        # 回收插件注册的扩展点，插件未进入运行态时同样按来源清理，避免残留
        if targets is None:
            self._unregister_plugin_extensions()
        else:
            self._unregister_extension_owners(targets)
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
                clear_plugin_modules(pid)
        else:
            # 清空
            self._plugins = {}
            self._running_plugins = {}
            # 清除所有插件模块缓存
            clear_plugin_modules()
        clear_plugin_agent_tools_cache()
        logger.info("插件停止完成")

    def _register_plugin_modules(self, pid: Optional[str] = None) -> None:
        """
        把插件经 provides_modules() 声明的系统模块注册进模块管理器

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        register_plugin_modules(self._running_plugins, ModuleManager, pid)

    def _register_plugin_extensions(self, pid: Optional[str] = None) -> None:
        """
        按最新声明注册插件的全部扩展点

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        register_plugin_extensions(self._running_plugins, ModuleManager, pid)

    def _extension_owners(self, pid: Optional[str] = None) -> List[str]:
        """
        列出需要回收扩展点的注册来源

        :param pid: 插件ID，为空时取全部已加载实例
        :return: 注册来源的实例键列表
        """
        return extension_owners(self._plugins, self._running_plugins, pid)

    def _unregister_plugin_modules(self, pid: Optional[str] = None) -> None:
        """
        回收插件注册的系统模块

        :param pid: 插件ID，为空时回收全部已加载实例
        """
        self._unregister_module_owners(self._extension_owners(pid))

    def _unregister_plugin_extensions(self, pid: Optional[str] = None) -> None:
        """
        回收插件注册的全部扩展点

        :param pid: 插件ID，为空时回收全部已加载实例
        """
        self._unregister_extension_owners(self._extension_owners(pid))

    @classmethod
    def _unregister_extension_owners(cls, owners: List[str]) -> None:
        """
        按注册来源回收全部扩展点

        :param owners: 注册来源的实例键列表
        """
        reclaim_extension_owners(owners, (cls._unregister_module_owners,
                                          unregister_capability_owners))

    @staticmethod
    def _unregister_module_owners(owners: List[str]) -> None:
        """
        按注册来源回收系统模块

        :param owners: 注册来源的实例键列表
        """
        unregister_module_owners(owners, ModuleManager.get_existing_instance)

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

    def get_local_plugins(self) -> List[schemas.Plugin]:
        """
        获取所有本地已下载的插件信息
        """
        # 返回值
        plugins = []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 一次取全部实例配置，避免逐插件查库
        try:
            instance_records = PluginConfigOper().list_all_instances()
        except Exception as err:
            logger.error(f"读取插件实例列表出错：{str(err)}")
            instance_records = {}
        for pid in self._distinct_plugin_ids(self._plugins):
            plugin_class = self.get_plugin_class(pid)
            # 基本属性、实例清单与运行状态
            plugin = build_plugin_summary(
                plugin_id=pid,
                plugin_class=plugin_class,
                installed=pid in installed_apps,
                instances=self._build_instance_view(pid, instance_records.get(pid, [])),
            )
            # 权限
            if not set_and_check_auth_level(plugin=plugin, source=plugin_class):
                continue
            # 展示属性
            apply_plugin_metadata(plugin, plugin_class)
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
        plugin_class = self.get_plugin_class(pid)
        if not plugin_class:
            return None
        return getattr(plugin_class, "plugin_version", None)
