"""本地插件清单条目的装配。

一行插件信息分两步拼出：概要部分承载认证校验所需的公钥与等级来源，展示属性在认证通过
后补齐。函数不持有任何注册表状态，插件类、安装状态与实例清单均由调用方传入。
"""
from typing import Any, Dict, List, Optional, Type

from app import schemas
from app.foundation.reflection import ObjectUtils


def build_plugin_summary(plugin_id: str, plugin_class: Optional[Type[Any]],
                         installed: bool, instances: List[Dict[str, Any]]) -> schemas.Plugin:
    """
    装配插件的概要信息

    :param plugin_id: 插件ID
    :param plugin_class: 插件类
    :param installed: 是否在已安装清单中
    :param instances: 该插件的实例清单
    :return: 已填入标识、安装状态、实例清单、运行状态、详情页标记与公钥的插件对象
    """
    plugin = schemas.Plugin()
    # ID
    plugin.id = plugin_id
    # 安装状态
    plugin.installed = installed
    # 实例清单
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
    return plugin


def apply_plugin_metadata(plugin: schemas.Plugin, plugin_class: Optional[Type[Any]]) -> None:
    """
    按插件类的声明补齐展示属性

    :param plugin: 待补齐的插件对象
    :param plugin_class: 插件类
    """
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
