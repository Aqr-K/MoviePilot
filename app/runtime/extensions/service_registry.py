from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Generic, Iterator

from app.db.oper.systemconfig import SystemConfigOper
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.service_config import ServiceConfigHelper
from app.schemas import ServiceInfo
from app.schemas.types import SystemConfigKey, ModuleType

TConf = TypeVar("TConf")

__all__ = [
    "ServiceBaseHelper",
    "ServiceConfigHelper",
    "SystemConfigOper",
]


# 各族的标志能力：族内全员实现、族外无实现的方法名，用作服务发现的判据。
#
# get_type() 只回答「你是什么」，但一个模块可能跨族兼任能力（媒体服务器兼任
# user_authenticate），按身份圈定服务集合天然会漏掉这类模块——不过就当前几族
# 而言，标志能力与身份圈出的集合是同一批模块，切换判据不改变发现结果。
#
# MediaRecognize 没有单一标志方法：7 个识别模块里 recognize_media 覆盖 6 个、
# media_detail 覆盖 5 个，两者并集才是全部 7 个，因此声明为多方法 OR 组。
#
# module_type 不在此表中的族在 _discover_modules 里回退到按身份查找，不强行
# 套用能力发现。
_FAMILY_CAPABILITIES: Dict[ModuleType, Tuple[str, ...]] = {
    ModuleType.Downloader: ("list_torrents",),
    ModuleType.MediaServer: ("user_authenticate",),
    ModuleType.Notification: ("post_message",),
    ModuleType.Indexer: ("search_torrents",),
    ModuleType.MediaRecognize: ("recognize_media", "media_detail"),
}


class ServiceBaseHelper(Generic[TConf]):
    """
    通用服务帮助类，抽象获取配置和服务实例的通用逻辑
    """

    def __init__(self, config_key: SystemConfigKey, conf_type: Type[TConf], module_type: ModuleType):
        """绑定服务配置类型与对应的运行模块类型。"""
        self.modulemanager = ModuleManager()
        self.config_key = config_key
        self.conf_type = conf_type
        self.module_type = module_type

    def get_configs(self, include_disabled: bool = False) -> Dict[str, TConf]:
        """
        获取配置列表

        :param include_disabled: 是否包含禁用的配置，默认 False（仅返回启用的配置）
        :return: 配置字典
        """
        configs: List[TConf] = ServiceConfigHelper.get_configs(self.config_key, self.conf_type)
        return {
            config.name: config
            for config in configs
            if (config.name and config.type and config.enabled) or include_disabled
        } if configs else {}

    def get_config(self, name: str) -> Optional[TConf]:
        """
        获取指定名称配置
        """
        if not name:
            return None
        configs = self.get_configs()
        return configs.get(name)

    def _discover_modules(self) -> Iterator[Any]:
        """
        发现本族运行模块

        module_type 命中 `_FAMILY_CAPABILITIES` 时按标志能力在 ModuleManager 的
        能力倒排索引上查找；OR 组的多个方法各查一次，按首次出现顺序去重合并——
        同一模块可能同时提供 OR 组里的多个方法，不能重复计入。未命中的族回退到
        按 module_type 身份查找，不强行套用能力发现。

        :return: 运行模块实例的迭代器
        """
        capabilities = _FAMILY_CAPABILITIES.get(self.module_type)
        if not capabilities:
            yield from self.modulemanager.get_running_type_modules(self.module_type)
            return
        seen = set()
        for method in capabilities:
            for module in self.modulemanager.providers_for(method):
                if module in seen:
                    continue
                seen.add(module)
                yield module

    def iterate_module_instances(self) -> Iterator[ServiceInfo]:
        """
        迭代所有模块的实例及其对应的配置，返回 ServiceInfo 实例
        """
        configs = self.get_configs()
        for module in self._discover_modules():
            if not module:
                continue
            module_instances = module.get_instances()
            if not isinstance(module_instances, dict):
                continue
            for name, instance in module_instances.items():
                if not instance:
                    continue
                config = configs.get(name)
                service_info = ServiceInfo(
                    name=name,
                    instance=instance,
                    module=module,
                    type=config.type if config else None,
                    config=config
                )
                yield service_info

    def get_services(self, type_filter: Optional[str] = None, name_filters: Optional[List[str]] = None) \
            -> Dict[str, ServiceInfo]:
        """
        获取服务信息列表，并根据类型和名称列表进行过滤

        :param type_filter: 需要过滤的服务类型
        :param name_filters: 需要过滤的服务名称列表
        :return: 过滤后的服务信息字典
        """
        name_filters_set = set(name_filters) if name_filters else None

        return {
            service_info.name: service_info
            for service_info in self.iterate_module_instances()
            if service_info.config and (
                    type_filter is None or service_info.type == type_filter
            ) and (
                       name_filters_set is None or service_info.name in name_filters_set)
        }

    def get_service(self, name: str, type_filter: Optional[str] = None) -> Optional[ServiceInfo]:
        """
        获取指定名称的服务信息，并根据类型过滤

        :param name: 服务名称
        :param type_filter: 需要过滤的服务类型
        :return: 对应的服务信息，若不存在或类型不匹配则返回 None
        """
        if not name:
            return None
        for service_info in self.iterate_module_instances():
            if service_info.name == name:
                if service_info.config and (type_filter is None or service_info.type == type_filter):
                    return service_info
        return None
