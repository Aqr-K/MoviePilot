# -*- coding: utf-8 -*-
"""
存储器单索引注册表（进程级、reload-stable、线程安全）= 内建 + 外部插件存储器的【唯一事实源】。

索引：{schema.value(str): _Entry(cls, owner)}，owner=None 为内建、其余为插件 owner。
schema.value 是存储路由身份（FileManagerModule 按它选后端），全局唯一——
故路由 = 一次 dict 查、注册碰撞检测 = 一次 dict 查，无需多表同步/全量重扫。

reload 稳定性：ModuleManager.load_modules() 只 importlib.reload app.modules 的【顶层】子包
（即 app.modules.filemanager 的 __init__），不递归重载本子模块，也不重载 storages 子包
（内建存储类身份稳定）。故本模块级索引不被重置：外部插件运行期注册的存储挺过 reload，
内建只扫一次。注册状态不挂在（可能被 reload 重建的）FileManagerModule 类上，而由本稳定模块持有。

线程安全：插件启停（PluginManager 线程）与 ModuleManager.load_modules（init_module→ensure_builtins）
可能并发；_REGISTRY/_builtins_loaded 由 _lock 保护，避免迭代时被并发写改坏（dict changed size）。
"""
import threading
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from app.core.module_loader import ModuleHelper


class _Entry(NamedTuple):
    cls: type
    owner: Optional[str]  # None=内建，其余=插件 owner


# {schema.value: _Entry}
_REGISTRY: Dict[str, _Entry] = {}
# 内建是否已扫描入索引（仅成功扫描后才置位，失败可重试）
_builtins_loaded: bool = False
# 保护 _REGISTRY 与 _builtins_loaded 的并发读写
_lock = threading.Lock()


def _schema_value(storage_class: type) -> Optional[str]:
    """取存储器类的 schema.value（路由身份），缺失返回 None。"""
    return getattr(getattr(storage_class, "schema", None), "value", None)


def ensure_builtins() -> None:
    """
    首次使用时扫描内建存储包并以 owner=None 入索引（幂等，仅一次）。
    内建存储类身份稳定（storages 子包不被 reload），故只扫一次即可长期缓存。

    扫描置于锁外（ModuleHelper.load 会 import/reload，较慢且不应持锁）；插入在锁内双检。
    仅在扫描+插入成功后才置 _builtins_loaded=True——若扫描抛异常，标志位保持 False、下次可重试，
    不会把内建永久标记为「已加载但为空」而使储存静默失效。
    ensure_builtins 直接用 setdefault 入索引、不回调 register，避免与 register→ensure_builtins 互递归。
    """
    global _builtins_loaded
    if _builtins_loaded:
        return
    scanned = ModuleHelper.load(
        "app.modules.filemanager.storages",
        filter_func=lambda _, obj: hasattr(obj, "schema") and obj.schema)
    with _lock:
        if _builtins_loaded:  # 双检：并发下另一线程可能已完成
            return
        for cls in scanned:
            value = _schema_value(cls)
            if value:
                _REGISTRY.setdefault(value, _Entry(cls, None))
        _builtins_loaded = True


def register(storage_class: type, owner: str) -> Tuple[bool, str]:
    """
    注册外部(插件)存储器类。schema.value 碰撞检测对齐 register_module 命名冲突：
    与内建(owner=None)或【其它】owner 占用同一 schema.value 即拒，同 owner 幂等放行。
    要求 storage_class 已通过 StorageBase 契约校验（由 FileManagerModule 负责）。

    :return: (是否接受, 失败原因)
    """
    if not owner or not isinstance(storage_class, type):
        return False, "非法入参（owner 为空或非类对象）"
    value = _schema_value(storage_class)
    if not value:
        return False, "缺少 schema.value"
    ensure_builtins()
    with _lock:
        existing = _REGISTRY.get(value)
        if existing is not None and existing.owner != owner:
            where = "内建存储" if existing.owner is None else f"owner={existing.owner}"
            return False, f"schema.value='{value}' 已被{where}占用"
        _REGISTRY[value] = _Entry(storage_class, owner)
    return True, ""


def unregister(owner: str) -> bool:
    """移除某来源(owner)注册的全部外部存储器。返回是否确有移除。内建(owner=None)不受影响。"""
    if not owner:
        return False
    with _lock:
        removed = [v for v, e in _REGISTRY.items() if e.owner == owner]
        for v in removed:
            _REGISTRY.pop(v, None)
    return bool(removed)


def get_class(schema_value: str) -> Optional[type]:
    """按 schema.value 取存储器类（路由）。O(1)。"""
    ensure_builtins()
    with _lock:
        entry = _REGISTRY.get(schema_value)
    return entry.cls if entry else None


def supported_values() -> Set[str]:
    """当前支持的全部 schema.value 集合（内建+外部）。"""
    ensure_builtins()
    with _lock:
        return set(_REGISTRY.keys())


def all_classes() -> List[type]:
    """全部存储器类（内建+外部）。"""
    ensure_builtins()
    with _lock:
        return [e.cls for e in _REGISTRY.values()]


def external_classes() -> List[type]:
    """仅外部(插件)注册的存储器类。"""
    ensure_builtins()
    with _lock:
        return [e.cls for e in _REGISTRY.values() if e.owner is not None]


def all_storages() -> List[type]:
    """[兼容别名] 仅外部(插件)注册的存储器类，等价 external_classes()。"""
    return external_classes()
