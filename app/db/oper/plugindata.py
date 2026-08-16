from typing import Any, Optional

from app.db import DbOper
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.db.models.plugindata import PluginData


class PluginDataOper(DbOper):
    """
    插件数据管理

    数据按 ``(plugin_id, instance_id, key)`` 寻址，未指定实例时落到默认实例。
    """

    def save(self, plugin_id: str, key: str, value: Any,
             instance_id: str = DEFAULT_INSTANCE_ID):
        """
        保存插件数据
        :param plugin_id: 插件id
        :param key: 数据key
        :param value: 数据值
        :param instance_id: 实例ID
        """
        plugin = PluginData.get_plugin_data_by_key(self._db, plugin_id, key, instance_id)
        if plugin:
            plugin.update(self._db, {
                "value": value
            })
        else:
            PluginData(plugin_id=plugin_id, instance_id=instance_id,
                       key=key, value=value).create(self._db)

    async def async_save(self, plugin_id: str, key: str, value: Any,
                         instance_id: str = DEFAULT_INSTANCE_ID) -> None:
        """
        异步保存插件数据

        :param plugin_id: 插件ID
        :param key: 数据键
        :param value: 数据值
        :param instance_id: 实例ID
        """
        plugin = await PluginData.async_get_plugin_data_by_key(
            self._db, plugin_id, key, instance_id
        )
        if plugin:
            await plugin.async_update(self._db, {"value": value})
        else:
            await PluginData(
                plugin_id=plugin_id, instance_id=instance_id, key=key, value=value
            ).async_create(self._db)

    def get_data(self, plugin_id: str, key: Optional[str] = None,
                 instance_id: str = DEFAULT_INSTANCE_ID) -> Any:
        """
        获取插件数据
        :param plugin_id: 插件id
        :param key: 数据key
        :param instance_id: 实例ID
        """
        if key:
            data = PluginData.get_plugin_data_by_key(self._db, plugin_id, key, instance_id)
            if not data:
                return None
            return data.value
        else:
            return PluginData.get_plugin_data(self._db, plugin_id, instance_id)

    async def async_get_data(self, plugin_id: str, key: Optional[str] = None,
                             instance_id: str = DEFAULT_INSTANCE_ID) -> Any:
        """
        异步获取插件数据。
        :param plugin_id: 插件id
        :param key: 数据key
        :param instance_id: 实例ID
        """
        if key:
            data = await PluginData.async_get_plugin_data_by_key(
                self._db, plugin_id, key, instance_id
            )
            if not data:
                return None
            return data.value
        return await PluginData.async_get_plugin_data(self._db, plugin_id, instance_id)

    def del_data(self, plugin_id: str, key: Optional[str] = None,
                 instance_id: Optional[str] = None) -> Any:
        """
        删除插件数据
        :param plugin_id: 插件id
        :param key: 数据key，为空时删除范围内的全部数据
        :param instance_id: 实例ID，为空时覆盖该插件的全部实例
        """
        if key:
            PluginData.del_plugin_data_by_key(self._db, plugin_id, key, instance_id)
        else:
            PluginData.del_plugin_data(self._db, plugin_id, instance_id)

    def truncate(self):
        """
        清空插件数据
        """
        PluginData.truncate(self._db)

    def get_data_all(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> Any:
        """
        获取插件所有数据
        :param plugin_id: 插件id
        :param instance_id: 实例ID
        """
        return PluginData.get_plugin_data_by_plugin_id(self._db, plugin_id, instance_id)

    async def async_get_data_all(self, plugin_id: str,
                                 instance_id: str = DEFAULT_INSTANCE_ID) -> Any:
        """
        异步获取插件所有数据。
        :param plugin_id: 插件id
        :param instance_id: 实例ID
        """
        return await PluginData.async_get_plugin_data_by_plugin_id(
            self._db, plugin_id, instance_id
        )
