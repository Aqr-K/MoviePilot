from datetime import datetime
from typing import Any, Dict, List, Optional

from app.db import DbOper
from app.db.models.pluginconfig import (
    DEFAULT_INSTANCE_ID,
    LOG_LEVELS,
    PluginConfig,
    normalize_instance_id,
)


def derive_enabled(config: Optional[Dict[str, Any]]) -> bool:
    """
    从插件配置中判定实例的启用状态

    enable 与 enabled 两种拼写都识别，前者优先；两者都不存在时视为未启用。
    :param config: 插件配置字典
    :return: 是否启用
    """
    if not isinstance(config, dict):
        return False
    if "enable" in config:
        return bool(config.get("enable"))
    if "enabled" in config:
        return bool(config.get("enabled"))
    return False


def resolve_log_level(log_level: Optional[str], log_expires_at: Optional[datetime],
                      global_level: str, now: Optional[datetime] = None) -> str:
    """
    计算插件实例当前生效的日志等级

    实例等级为空、取值不合法或已过期时回落到全局等级。
    :param log_level: 实例独立的日志等级
    :param log_expires_at: 实例日志等级的失效时间，为空表示不过期
    :param global_level: 全局日志等级
    :param now: 参与过期判定的当前时间，缺省取系统当前时间
    :return: 生效的日志等级
    """
    if not log_level:
        return global_level
    level = str(log_level).upper()
    if level not in LOG_LEVELS:
        return global_level
    if log_expires_at is not None and (now or datetime.now()) >= log_expires_at:
        return global_level
    return level


class PluginConfigOper(DbOper):
    """
    插件实例配置管理

    一条配置由 ``(plugin_id, instance_id)`` 唯一确定，读写一律直达数据库，
    使插件自身与插件管理器两个入口看到同一份数据。
    """

    def get_instance(self, plugin_id: str,
                     instance_id: str = DEFAULT_INSTANCE_ID) -> Optional[PluginConfig]:
        """
        获取插件实例的配置记录
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 配置记录，无则 None
        """
        return PluginConfig.get_instance(self._db, plugin_id, normalize_instance_id(instance_id))

    def get(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> Optional[dict]:
        """
        获取插件实例的业务配置
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 配置字典，无记录时为 None
        """
        record = self.get_instance(plugin_id, instance_id)
        return record.config_data if record else None

    async def async_get(self, plugin_id: str,
                        instance_id: str = DEFAULT_INSTANCE_ID) -> Optional[dict]:
        """
        异步获取插件实例的业务配置
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 配置字典，无记录时为 None
        """
        record = await PluginConfig.async_get_instance(
            self._db, plugin_id, normalize_instance_id(instance_id)
        )
        return record.config_data if record else None

    def set(self, plugin_id: str, config: Optional[dict],
            instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        写入插件实例的业务配置，记录不存在时创建

        启用状态由配置内容推导，日志等级等实例属性保持不变。
        :param plugin_id: 插件ID
        :param config: 配置字典
        :param instance_id: 实例ID
        :return: 是否写入成功
        """
        instance_id = normalize_instance_id(instance_id)
        payload = {"config_data": config, "is_enabled": derive_enabled(config)}
        record = PluginConfig.get_instance(self._db, plugin_id, instance_id)
        if record:
            record.update(self._db, payload)
        else:
            PluginConfig(plugin_id=plugin_id, instance_id=instance_id, **payload).create(self._db)
        return True

    async def async_set(self, plugin_id: str, config: Optional[dict],
                        instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        异步写入插件实例的业务配置，记录不存在时创建
        :param plugin_id: 插件ID
        :param config: 配置字典
        :param instance_id: 实例ID
        :return: 是否写入成功
        """
        instance_id = normalize_instance_id(instance_id)
        payload = {"config_data": config, "is_enabled": derive_enabled(config)}
        record = await PluginConfig.async_get_instance(self._db, plugin_id, instance_id)
        if record:
            await record.async_update(self._db, payload)
        else:
            await PluginConfig(
                plugin_id=plugin_id, instance_id=instance_id, **payload
            ).async_create(self._db)
        return True

    def delete(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        删除插件单个实例的配置
        :param plugin_id: 插件ID
        :param instance_id: 实例ID
        :return: 是否删除成功
        """
        PluginConfig.delete_instance(self._db, plugin_id, normalize_instance_id(instance_id))
        return True

    def delete_plugin(self, plugin_id: str) -> bool:
        """
        删除插件全部实例的配置
        :param plugin_id: 插件ID
        :return: 是否删除成功
        """
        PluginConfig.delete_plugin(self._db, plugin_id)
        return True

    def list_instances(self, plugin_id: str) -> List[PluginConfig]:
        """
        列出插件的全部实例配置
        :param plugin_id: 插件ID
        :return: 按实例ID升序排列的配置记录
        """
        return PluginConfig.list_by_plugin(self._db, plugin_id)

    def list_all_instances(self) -> Dict[str, List[PluginConfig]]:
        """
        一次取出全部插件的实例配置并按插件归组
        :return: {插件ID: [按实例ID升序排列的配置记录]}
        """
        grouped: Dict[str, List[PluginConfig]] = {}
        for record in PluginConfig.list_all(self._db) or []:
            if not record.plugin_id:
                continue
            grouped.setdefault(record.plugin_id, []).append(record)
        return grouped

    def set_log_level(self, plugin_id: str, log_level: Optional[str],
                      expires_at: Optional[datetime] = None,
                      instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        设置插件实例的独立日志等级，记录不存在时创建
        :param plugin_id: 插件ID
        :param log_level: 日志等级，为空时跟随全局等级
        :param expires_at: 日志等级的失效时间，为空表示不过期
        :param instance_id: 实例ID
        :return: 是否设置成功
        :raises ValueError: 日志等级不在合法取值内
        """
        if log_level is not None and str(log_level).upper() not in LOG_LEVELS:
            raise ValueError(f"非法的插件日志等级：{log_level}")
        instance_id = normalize_instance_id(instance_id)
        payload = {
            "log_level": str(log_level).upper() if log_level else None,
            "log_expires_at": expires_at,
        }
        record = PluginConfig.get_instance(self._db, plugin_id, instance_id)
        if record:
            record.update(self._db, payload)
        else:
            PluginConfig(plugin_id=plugin_id, instance_id=instance_id,
                         is_enabled=False, **payload).create(self._db)
        return True

    def get_log_level(self, plugin_id: str, global_level: str,
                      instance_id: str = DEFAULT_INSTANCE_ID,
                      now: Optional[datetime] = None) -> str:
        """
        获取插件实例当前生效的日志等级
        :param plugin_id: 插件ID
        :param global_level: 全局日志等级
        :param instance_id: 实例ID
        :param now: 参与过期判定的当前时间，缺省取系统当前时间
        :return: 生效的日志等级
        """
        record = self.get_instance(plugin_id, instance_id)
        if not record:
            return global_level
        return resolve_log_level(record.log_level, record.log_expires_at, global_level, now)
