"""插件扩展点的注册与回收。

插件声明的系统模块、存储实现与渠道能力在实例上线时按实例键注册，在实例下线时按同一个
实例键回收，因此同一插件的多个实例互不覆盖、也互不牵连。各函数不持有任何注册表状态，
运行态插件表、注册来源与模块管理器均由调用方传入。
"""
from typing import Any, Callable, Dict, Iterable, List, Optional

from app.runtime.extensions.plugin_instance import instance_key, plugin_id_of
from app.runtime.extensions.plugin_spi import (
    get_plugin_provided_channel_capabilities,
    get_plugin_provided_modules,
    get_plugin_provided_storages,
)
from app.runtime.log import logger
from app.schemas.message import ChannelCapabilityManager


def register_plugin_modules(running_plugins: Dict[str, Any],
                            create_module_manager: Callable[[], Any],
                            pid: Optional[str] = None) -> None:
    """
    把插件经 provides_modules() 声明的系统模块注册进模块管理器

    无插件声明模块时不取模块管理器，避免提前触发模块全量装载。

    :param running_plugins: 运行态插件表 {实例键: 插件实例}
    :param create_module_manager: 取模块管理器的工厂，无参调用
    :param pid: 插件ID或实例键，为空时处理全部运行态实例
    """
    provided = get_plugin_provided_modules(running_plugins, pid)
    if not provided:
        return
    module_manager = create_module_manager()
    for key, modules in provided.items():
        for module in modules:
            module_manager.register_module(module, owner=key)


def register_plugin_storages(running_plugins: Dict[str, Any],
                             pid: Optional[str] = None) -> None:
    """
    把插件经 provides_storages() 声明的存储实现注册进存储注册表

    无插件声明存储时不触碰存储层，避免提前触发存储驱动装载。

    :param running_plugins: 运行态插件表 {实例键: 插件实例}
    :param pid: 插件ID或实例键，为空时处理全部运行态实例
    """
    provided = get_plugin_provided_storages(running_plugins, pid)
    if not provided:
        return
    from app.adapters.storage.registry import register_storage
    for key, storages in provided.items():
        for storage in storages:
            register_storage(storage, owner=key)


def register_plugin_channel_capabilities(running_plugins: Dict[str, Any],
                                         pid: Optional[str] = None) -> None:
    """
    把插件经 provides_channel_capabilities() 声明的渠道能力注册进渠道能力管理器

    :param running_plugins: 运行态插件表 {实例键: 插件实例}
    :param pid: 插件ID或实例键，为空时处理全部运行态实例
    """
    provided = get_plugin_provided_channel_capabilities(running_plugins, pid)
    if not provided:
        return
    for key, capabilities in provided.items():
        for capability in capabilities:
            if ChannelCapabilityManager.register_capabilities(capability, owner=key):
                continue
            channel = getattr(capability, "channel", capability)
            logger.warning(f"插件 {key} 声明的渠道能力 {channel} 未被接受")


def register_plugin_extensions(running_plugins: Dict[str, Any],
                               create_module_manager: Callable[[], Any],
                               pid: Optional[str] = None) -> None:
    """
    按最新声明注册插件的全部扩展点

    :param running_plugins: 运行态插件表 {实例键: 插件实例}
    :param create_module_manager: 取模块管理器的工厂，无参调用
    :param pid: 插件ID或实例键，为空时处理全部运行态实例
    """
    register_plugin_modules(running_plugins, create_module_manager, pid)
    register_plugin_storages(running_plugins, pid)
    register_plugin_channel_capabilities(running_plugins, pid)


def extension_owners(plugins: Dict[str, Any],
                     running_plugins: Dict[str, Any],
                     pid: Optional[str] = None) -> List[str]:
    """
    列出需要回收扩展点的注册来源

    插件加载失败时不会进入任何容器，此时按其默认实例键回收可能残留的注册。

    :param plugins: 插件类表 {实例键: 插件类}
    :param running_plugins: 运行态插件表 {实例键: 插件实例}
    :param pid: 插件ID，为空时取全部已登记实例
    :return: 注册来源的实例键列表
    """
    loaded = list({**plugins, **running_plugins})
    if not pid:
        return loaded
    return [key for key in loaded if plugin_id_of(key) == pid] or [instance_key(pid)]


def unregister_module_owners(owners: List[str],
                             find_module_manager: Callable[[], Optional[Any]]) -> None:
    """
    按注册来源回收系统模块

    模块管理器尚未装载时无模块可回收，直接返回。

    :param owners: 注册来源的实例键列表
    :param find_module_manager: 取已有模块管理器的查询，无参调用，未装载时返回 None
    """
    module_manager = find_module_manager()
    if module_manager is None:
        return
    for owner in owners:
        removed = module_manager.unregister_modules(owner)
        if removed:
            logger.info(f"已回收插件 {owner} 注册的模块：{'、'.join(removed)}")


def unregister_storage_owners(owners: List[str]) -> None:
    """
    按注册来源回收存储实现

    :param owners: 注册来源的实例键列表
    """
    from app.adapters.storage.registry import unregister_storages
    for owner in owners:
        removed = unregister_storages(owner)
        if removed:
            logger.info(f"已回收插件 {owner} 注册的存储：{'、'.join(removed)}")


def unregister_capability_owners(owners: List[str]) -> None:
    """
    按注册来源回收渠道能力

    :param owners: 注册来源的实例键列表
    """
    for owner in owners:
        removed = ChannelCapabilityManager.unregister_capabilities(owner)
        if removed:
            logger.info(f"已回收插件 {owner} 注册的渠道能力："
                        f"{'、'.join(channel.value for channel in removed)}")


def reclaim_extension_owners(owners: List[str],
                             reclaimers: Iterable[Callable[[List[str]], None]]) -> None:
    """
    依次执行各类扩展点的回收

    每类扩展点各自隔离，任一回收失败都不得连累其余。

    :param owners: 注册来源的实例键列表
    :param reclaimers: 各类扩展点的回收动作，逐个接收注册来源列表
    """
    for reclaim in reclaimers:
        try:
            reclaim(owners)
        except Exception as err:
            logger.error(f"回收插件扩展点出错：{str(err)}", exc_info=True)
