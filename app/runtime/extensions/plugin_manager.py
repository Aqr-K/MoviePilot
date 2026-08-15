import asyncio
import inspect
import shutil
import traceback
from typing import Any, Dict, List, Optional, Type

from app import schemas
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.db.oper.systemconfig import SystemConfigOper
from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton
from app.runtime.log import logger
from app.runtime.config import settings
from app.runtime.events import EventHandlerBinding, eventmanager
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_auth import set_and_check_auth_level
from app.runtime.extensions.plugin_instance import (
    instance_key,
    plugin_id_of,
    resolve_running_plugin,
    split_instance_key,
)
from app.runtime.extensions.plugin_loader import (
    apply_legacy_import_diagnostics,
    clear_plugin_modules,
    load_selective_plugins,
)
from app.runtime.extensions.plugin_spi import (
    clear_plugin_agent_tools_cache,
    get_plugin_provided_channel_capabilities,
    get_plugin_provided_modules,
    get_plugin_provided_storages,
)
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import EventType, SystemConfigKey


class PluginManager(metaclass=Singleton):
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

    def get_plugin_class(self, plugin_id: str) -> Optional[Type[Any]]:
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

    def get_running_plugin(self, key: str) -> Optional[Any]:
        """
        按实例键或插件ID取运行实例

        插件只有分身实例时，按插件ID同样能取到实例。

        :param key: 实例键或插件ID
        :return: 插件实例，未运行时为 None
        """
        return resolve_running_plugin(self._running_plugins, key)

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
        self._register_plugin_extensions(pid)
        clear_plugin_agent_tools_cache()

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

    def _register_plugin_storages(self, pid: Optional[str] = None) -> None:
        """
        把插件经 provides_storages() 声明的存储实现注册进存储注册表

        无插件声明存储时不触碰存储层，避免提前触发存储驱动装载。

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        provided = get_plugin_provided_storages(self._running_plugins, pid)
        if not provided:
            return
        from app.adapters.storage.registry import register_storage
        for key, storages in provided.items():
            for storage in storages:
                register_storage(storage, owner=key)

    def _register_plugin_channel_capabilities(self, pid: Optional[str] = None) -> None:
        """
        把插件经 provides_channel_capabilities() 声明的渠道能力注册进渠道能力管理器

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        provided = get_plugin_provided_channel_capabilities(self._running_plugins, pid)
        if not provided:
            return
        for key, capabilities in provided.items():
            for capability in capabilities:
                if ChannelCapabilityManager.register_capabilities(capability, owner=key):
                    continue
                channel = getattr(capability, "channel", capability)
                logger.warning(f"插件 {key} 声明的渠道能力 {channel} 未被接受")

    def _register_plugin_extensions(self, pid: Optional[str] = None) -> None:
        """
        按最新声明注册插件的全部扩展点

        :param pid: 插件ID或实例键，为空时处理全部运行态实例
        """
        self._register_plugin_modules(pid)
        self._register_plugin_storages(pid)
        self._register_plugin_channel_capabilities(pid)

    def _extension_owners(self, pid: Optional[str] = None) -> List[str]:
        """
        列出需要回收扩展点的注册来源

        :param pid: 插件ID，为空时取全部已加载实例
        :return: 注册来源的实例键列表
        """
        if pid:
            return self.get_instance_keys(pid) or [instance_key(pid)]
        return list({**self._plugins, **self._running_plugins})

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

        每类扩展点各自隔离，任一回收失败都不得连累其余。

        :param owners: 注册来源的实例键列表
        """
        for reclaim in (cls._unregister_module_owners,
                        cls._unregister_storage_owners,
                        cls._unregister_capability_owners):
            try:
                reclaim(owners)
            except Exception as err:
                logger.error(f"回收插件扩展点出错：{str(err)}", exc_info=True)

    @staticmethod
    def _unregister_storage_owners(owners: List[str]) -> None:
        """
        按注册来源回收存储实现

        :param owners: 注册来源的实例键列表
        """
        from app.adapters.storage.registry import unregister_storages
        for owner in owners:
            removed = unregister_storages(owner)
            if removed:
                logger.info(f"已回收插件 {owner} 注册的存储：{'、'.join(removed)}")

    @staticmethod
    def _unregister_capability_owners(owners: List[str]) -> None:
        """
        按注册来源回收渠道能力

        :param owners: 注册来源的实例键列表
        """
        for owner in owners:
            removed = ChannelCapabilityManager.unregister_capabilities(owner)
            if removed:
                logger.info(f"已回收插件 {owner} 注册的渠道能力："
                            f"{'、'.join(channel.value for channel in removed)}")

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

    def delete_plugin_config(self, pid: str, force: bool = False,
                             instance_id: Optional[str] = None) -> bool:
        """
        删除插件配置
        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化配置
        :param instance_id: 实例ID，为空时清除该插件的全部实例
        :return: 是否删除成功
        :raises ValueError: 实例标识含非法字符或超长
        """
        normalized = normalize_instance_id(instance_id) if instance_id is not None else None
        if not force and not self.has_plugin(pid):
            return False
        if normalized is None:
            return PluginConfigOper().delete_plugin(pid)
        return PluginConfigOper().delete(pid, normalized)

    def delete_plugin_data(self, pid: str, force: bool = False,
                           instance_id: Optional[str] = None) -> bool:
        """
        删除插件数据

        自管理库由同插件的全部实例共享，只在删除整个插件的数据时一并删除。

        :param pid: 插件ID
        :param force: 插件停止后仍允许按插件 ID 删除持久化数据
        :param instance_id: 实例ID，为空时清除该插件的全部实例
        :return: 是否删除成功
        :raises ValueError: 实例标识含非法字符或超长
        """
        normalized = normalize_instance_id(instance_id) if instance_id is not None else None
        if not force and not self.has_plugin(pid):
            return False
        if normalized is None:
            PluginDataOper().del_data(pid)
            self._drop_plugin_database(pid)
            return True
        PluginDataOper().del_data(pid, instance_id=normalized)
        return True

    @staticmethod
    def _drop_plugin_database(pid: str) -> None:
        """
        删除插件自管理的独立库，失败不影响已完成的数据清理

        :param pid: 插件ID
        """
        try:
            from app.db.plugin import teardown_plugin_database
            teardown_plugin_database(pid)
        except Exception as err:
            logger.error(f"删除插件 {pid} 自管理数据库出错：{str(err)}")

    @staticmethod
    def _stored_instance_ids(pid: str) -> List[str]:
        """
        列出插件已落库的实例标识，未落库的隐式默认实例不在其中

        :param pid: 插件ID
        :return: 按落库顺序去重的实例标识列表
        """
        try:
            records = PluginConfigOper().list_instances(pid) or []
        except Exception as err:
            logger.error(f"读取插件 {pid} 实例列表出错：{str(err)}")
            return []
        stored = []
        for record in records:
            if not record.instance_id:
                continue
            try:
                normalized = normalize_instance_id(record.instance_id)
            except ValueError as err:
                logger.error(f"跳过插件 {pid} 的非法实例配置：{str(err)}")
                continue
            if normalized not in stored:
                stored.append(normalized)
        return stored

    def reset_plugin(self, pid: str, instance_id: Optional[str] = None) -> bool:
        """
        清空插件的配置与数据，已创建的实例定义保留

        实例定义是用户资产：清空后各实例仍在，只是配置回到空、数据被删除。数据目录不在
        清空范围内，与默认实例重置不动插件目录保持一致。自管理库由同插件的全部实例共享，
        只在整插件清空时删除。

        :param pid: 插件ID
        :param instance_id: 实例ID，为空时清空该插件的全部实例
        :return: 是否清空成功
        :raises ValueError: 实例标识含非法字符或超长
        """
        config_oper = PluginConfigOper()
        data_oper = PluginDataOper()
        stored_ids = self._stored_instance_ids(pid)

        if instance_id is None:
            config_oper.delete_plugin(pid)
            data_oper.del_data(pid)
            self._drop_plugin_database(pid)
            # 只有存在分身时才需要显式补回实例定义：单实例插件的默认实例本就隐式存在，
            # 补一行空配置反而会让存量插件的重置结果与升级前不同
            if any(stored != DEFAULT_INSTANCE_ID for stored in stored_ids):
                for stored in stored_ids:
                    config_oper.set(pid, {}, stored)
            return True

        normalized = normalize_instance_id(instance_id)
        config_oper.delete(pid, normalized)
        data_oper.del_data(pid, instance_id=normalized)
        if normalized in stored_ids:
            config_oper.set(pid, {}, normalized)
        return True

    def get_plugin_instances(self, plugin_id: str) -> List[Dict[str, Any]]:
        """
        列出插件的全部实例及其状态
        [{
            "plugin_id": "插件ID",
            "instance_id": "实例ID",
            "instance_key": "实例键",
            "is_default": True,
            "running": True,
            "enabled": True
        }]

        一个实例都没有配置时按默认实例呈现，与拉起逻辑一致。

        :param plugin_id: 插件ID
        :return: 实例列表
        """
        try:
            records = PluginConfigOper().list_instances(plugin_id) or []
        except Exception as err:
            logger.error(f"读取插件 {plugin_id} 实例列表出错：{str(err)}")
            records = []
        return self._build_instance_view(plugin_id, records)

    def _build_instance_view(self, plugin_id: str, records: List[Any]) -> List[Dict[str, Any]]:
        """
        按落库配置与运行态拼出插件的实例视图

        :param plugin_id: 插件ID
        :param records: 该插件的实例配置记录
        :return: 实例列表，一个实例都没有配置时按默认实例呈现
        """
        configured: Dict[str, bool] = {}
        for record in records:
            try:
                normalized = normalize_instance_id(record.instance_id)
            except ValueError as err:
                logger.error(f"跳过插件 {plugin_id} 的非法实例配置：{str(err)}")
                continue
            configured[normalized] = bool(record.is_enabled)
        instance_ids = list(configured)
        for key in self.get_instance_keys(plugin_id):
            running_instance_id = split_instance_key(key)[1]
            if running_instance_id not in instance_ids:
                instance_ids.append(running_instance_id)
        if not instance_ids:
            instance_ids = [DEFAULT_INSTANCE_ID]
        instances = []
        for instance_id in instance_ids:
            key = instance_key(plugin_id, instance_id)
            plugin = self._running_plugins.get(key)
            if plugin is not None:
                try:
                    enabled = bool(plugin.get_state())
                except Exception as err:
                    logger.error(f"获取插件实例 {key} 状态出错：{str(err)}")
                    enabled = False
            else:
                enabled = configured.get(instance_id, False)
            instances.append({
                "plugin_id": plugin_id,
                "instance_id": instance_id,
                "instance_key": key,
                "is_default": instance_id == DEFAULT_INSTANCE_ID,
                "running": plugin is not None,
                "enabled": enabled,
            })
        return instances

    def create_plugin_instance(self, plugin_id: str, instance_id: str,
                               config: Optional[dict] = None) -> str:
        """
        创建插件实例并写入其初始配置

        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :param config: 实例的初始配置
        :return: 新实例的实例键
        :raises ValueError: 实例标识非法、指向默认实例或实例已存在
        """
        normalized = normalize_instance_id(instance_id)
        if normalized == DEFAULT_INSTANCE_ID:
            raise ValueError("默认实例随插件自动创建，不能重复创建")
        config_oper = PluginConfigOper()
        if config_oper.get_instance(plugin_id, normalized):
            raise ValueError(f"插件 {plugin_id} 的实例 {normalized} 已存在")
        # 首个分身落库前先固化默认实例，避免默认实例因没有配置记录而在下次启动时缺席
        if not config_oper.list_instances(plugin_id):
            config_oper.set(plugin_id, self.get_plugin_config(plugin_id), DEFAULT_INSTANCE_ID)
        config_oper.set(plugin_id, config or {}, normalized)
        return instance_key(plugin_id, normalized)

    def delete_plugin_instance(self, plugin_id: str, instance_id: str) -> str:
        """
        删除插件实例，停止运行态并清除该实例的配置、数据与数据目录

        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 被删除实例的实例键
        :raises ValueError: 实例标识非法或指向默认实例
        """
        normalized = normalize_instance_id(instance_id)
        if normalized == DEFAULT_INSTANCE_ID:
            raise ValueError("默认实例不允许删除")
        key = instance_key(plugin_id, normalized)
        self.stop(plugin_id, normalized)
        PluginConfigOper().delete(plugin_id, normalized)
        PluginDataOper().del_data(plugin_id, instance_id=normalized)
        self._remove_instance_data_path(plugin_id, normalized)
        return key

    @staticmethod
    def _remove_instance_data_path(plugin_id: str, instance_id: str) -> None:
        """
        回收插件实例独占的数据目录

        默认实例的数据目录就是插件目录本身，由插件级操作负责，这里只处理分身独占的
        ``PLUGIN_DATA_PATH/<plugin_id>/instances/<instance_id>``。

        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        """
        if instance_id == DEFAULT_INSTANCE_ID:
            return
        plugin_path = settings.PLUGIN_DATA_PATH / plugin_id
        data_path = plugin_path / "instances" / instance_id
        try:
            # 实例标识拼进路径，落点必须仍在插件目录之内且不是插件目录本身
            resolved = data_path.resolve()
            if resolved == plugin_path.resolve() or not resolved.is_relative_to(plugin_path.resolve()):
                logger.error(f"拒绝回收插件 {plugin_id} 实例 {instance_id} 的目录：{resolved}")
                return
            if not resolved.is_dir():
                return
            shutil.rmtree(resolved)
        except Exception as err:
            logger.error(f"回收插件 {plugin_id} 实例 {instance_id} 数据目录出错：{str(err)}")

    def get_plugin_state(self, pid: str) -> bool:
        """
        获取插件状态
        :param pid: 插件ID或实例键
        """
        plugin = resolve_running_plugin(self._running_plugins, pid)
        return plugin.get_state() if plugin else False

    def get_plugin_attr(self, pid: str, attr: str) -> Any:
        """
        获取插件属性
        :param pid: 插件ID或实例键
        :param attr: 属性名
        """
        plugin = resolve_running_plugin(self._running_plugins, pid)
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
        plugin = resolve_running_plugin(self._running_plugins, pid)
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
        plugin = resolve_running_plugin(self._running_plugins, pid)
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
            # 基本属性
            plugin = schemas.Plugin()
            # ID
            plugin.id = pid
            # 安装状态
            if pid in installed_apps:
                plugin.installed = True
            else:
                plugin.installed = False
            # 实例清单
            instances = self._build_instance_view(pid, instance_records.get(pid, []))
            plugin.instances = [schemas.PluginInstance(**instance) for instance in instances]
            # 运行状态，任一实例已进入运行态且启用即视为该插件在运行；
            # 只在配置里启用但没能加载起来的插件不算
            plugin.state = any(instance["running"] and instance["enabled"]
                               for instance in instances)
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
            if not set_and_check_auth_level(plugin=plugin, source=plugin_class):
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
        plugin_class = self.get_plugin_class(pid)
        if not plugin_class:
            return None
        return getattr(plugin_class, "plugin_version", None)
