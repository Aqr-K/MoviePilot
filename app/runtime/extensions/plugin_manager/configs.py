"""插件配置与数据的读写、清空和自管理库处置。

配置与数据都按实例隔离，实例ID为空时作用于该插件的全部实例。自管理库由同一插件的全部
实例共享，因此只在整插件级别释放连接或删库。
"""
from typing import Any, Dict, List, Optional

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.runtime.log import logger


class PluginConfigMixin:
    """插件配置与数据的读写面。"""

    _running_plugins: Dict[str, Any]

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
