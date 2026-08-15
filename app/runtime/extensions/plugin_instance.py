"""插件实例在运行期的标识。

运行期容器、模块注册来源与事件启停都以实例键定位一个插件实例。默认实例的实例键退化为
裸插件标识，因此单实例插件的取值与不区分实例时完全一致。
"""
from typing import Optional, Tuple

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id

# 实例键中插件标识与实例标识的分隔符，插件类名与实例标识的字符集都不含该字符
INSTANCE_KEY_SEPARATOR = "@"


def instance_key(plugin_id: str, instance_id: Optional[str] = None) -> str:
    """
    组合插件实例在运行期的唯一键

    :param plugin_id: 插件标识
    :param instance_id: 实例标识，为空时取默认实例
    :return: 默认实例返回裸插件标识，其余返回 ``plugin_id@instance_id``
    :raises ValueError: 实例标识含非法字符或超长
    """
    normalized = normalize_instance_id(instance_id)
    if normalized == DEFAULT_INSTANCE_ID:
        return plugin_id
    return f"{plugin_id}{INSTANCE_KEY_SEPARATOR}{normalized}"


def split_instance_key(key: str) -> Tuple[str, str]:
    """
    反解实例键

    :param key: 实例键
    :return: ``(插件标识, 实例标识)``，裸插件标识对应默认实例
    """
    plugin_id, separator, suffix = key.partition(INSTANCE_KEY_SEPARATOR)
    if not separator or not suffix:
        return key, DEFAULT_INSTANCE_ID
    return plugin_id, suffix


def plugin_id_of(key: str) -> str:
    """
    取实例键所属的插件标识

    :param key: 实例键
    :return: 插件标识
    """
    return split_instance_key(key)[0]


def matches_plugin(key: str, pid: Optional[str]) -> bool:
    """
    判断实例键是否命中筛选条件

    :param key: 实例键
    :param pid: 插件标识或实例键，插件标识命中该插件的全部实例，为空时命中全部
    :return: 是否命中
    """
    if not pid:
        return True
    return key == pid or plugin_id_of(key) == pid


def is_default_instance_key(key: str) -> bool:
    """
    判断实例键是否指向默认实例

    :param key: 实例键
    :return: 是否为默认实例
    """
    return split_instance_key(key)[1] == DEFAULT_INSTANCE_ID


def qualify_module_id(module_id: str, owner: str) -> str:
    """
    按注册来源限定模块标识

    默认实例保持裸模块标识，与内建模块共用同一套命名；非默认实例追加实例键，使同一插件
    的多个实例注册同一个模块类时互不覆盖。

    :param module_id: 模块自身声明的标识
    :param owner: 注册来源的实例键
    :return: 限定后的模块标识
    """
    if is_default_instance_key(owner):
        return module_id
    return f"{module_id}{INSTANCE_KEY_SEPARATOR}{owner}"
