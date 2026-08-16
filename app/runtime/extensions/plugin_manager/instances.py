"""插件实例的构造、清单与增删。

实例定义落在插件配置表里，一条记录即一个实例；没有任何记录的插件按默认实例处理，因此
未创建分身的插件与单实例时代表现一致。分身独占的数据目录随实例一起回收。
"""
import inspect
import shutil
from typing import Any, Dict, List, Optional, Type

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.runtime.config import settings
from app.runtime.extensions.plugin_instance import instance_key, split_instance_key
from app.runtime.log import logger


class PluginInstanceMixin:
    """插件实例的构造与管理面。"""

    _running_plugins: Dict[str, Any]

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
