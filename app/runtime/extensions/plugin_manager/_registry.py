"""插件运行态注册表的查询与调用。

插件类表与运行态实例表都以实例键为键，同一插件的多个实例各占一个键。这里只读取两张
表并按实例键或插件ID解析目标，不改动注册表内容。
"""
import asyncio
from typing import Any, Dict, List, Optional, Type

from app.runtime.events import EventHandlerBinding
from app.runtime.extensions.plugin_instance import (
    is_default_instance_key,
    plugin_id_of,
    resolve_running_plugin,
)
from app.runtime.log import logger


class _PluginRegistryMixin:
    """插件注册表的查询面。"""

    # 插件列表，键为实例键，值为插件类；同一个类会被该插件的全部实例键指向
    _plugins: Dict[str, Any]
    # 运行态插件列表，键为实例键，值为插件实例
    _running_plugins: Dict[str, Any]

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

    def get_plugin_state(self, pid: str) -> bool:
        """
        获取插件运行状态

        传实例键时判定该实例；传插件标识时任一运行实例启用即为 True，与插件列表的
        运行状态取值一致。

        :param pid: 插件ID或实例键
        :return: 是否有已启用的运行实例
        """
        if not is_default_instance_key(pid):
            plugin = self._running_plugins.get(pid)
            return self._instance_enabled(pid, plugin) if plugin is not None else False
        return any(self._instance_enabled(key, running)
                   for key, running in dict(self._running_plugins).items()
                   if plugin_id_of(key) == pid)

    @staticmethod
    def _instance_enabled(key: str, plugin: Any) -> bool:
        """
        取单个实例的启用状态，取值失败按未启用处理

        :param key: 实例键
        :param plugin: 插件实例
        :return: 是否启用
        """
        try:
            return bool(plugin.get_state())
        except Exception as err:
            logger.error(f"获取插件实例 {key} 状态出错：{str(err)}")
            return False

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
