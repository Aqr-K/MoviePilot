# -*- coding: utf-8 -*-
"""
外部(插件)存储器注册表（进程级，reload-stable）。

存于本独立子模块的模块级全局：ModuleManager.load_modules() 只对 app.modules 的【顶层】子包
做 importlib.reload（即重载 app.modules.filemanager 的 __init__），不会递归重载本子模块，
故本注册表全局字典不被重置——使运行期插件注册的存储器挺过 ModuleManager.reload()。

同时规避 reload 造成的 FileManagerModule 类对象分叉：注册状态不挂在（可能被重建的）类上，
而由本稳定模块持有，FileManagerModule.init_module 始终从这里读取外部存储器。
"""
from typing import Dict, List, Optional

# {owner: [storage_class, ...]}
_EXTERNAL_STORAGES: Dict[str, List[type]] = {}


def register(storage_class: type, owner: str) -> bool:
    """记账一个外部存储器类（按 owner）。幂等：同 owner 重复注册不产生重复记录。"""
    if not owner or not isinstance(storage_class, type):
        return False
    _EXTERNAL_STORAGES.setdefault(owner, [])
    if storage_class not in _EXTERNAL_STORAGES[owner]:
        _EXTERNAL_STORAGES[owner].append(storage_class)
    return True


def unregister(owner: str) -> bool:
    """移除某来源(owner)的全部外部存储器记账。返回是否确有移除。"""
    if not owner:
        return False
    return _EXTERNAL_STORAGES.pop(owner, None) is not None


def all_storages() -> List[type]:
    """返回所有外部存储器类（跨 owner 展平）。"""
    return [cls for classes in _EXTERNAL_STORAGES.values() for cls in classes]


def schema_owner(schema_value: str, exclude_owner: Optional[str] = None) -> Optional[str]:
    """
    返回声明了该 schema.value（存储路由身份）的外部 owner；无则 None。
    exclude_owner 用于排除某来源（如注册自检时排除自身 owner，避免幂等重注册误判冲突）。
    """
    for owner, classes in _EXTERNAL_STORAGES.items():
        if exclude_owner is not None and owner == exclude_owner:
            continue
        for cls in classes:
            if getattr(getattr(cls, "schema", None), "value", None) == schema_value:
                return owner
    return None
