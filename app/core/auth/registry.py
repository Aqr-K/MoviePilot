# -*- coding: utf-8 -*-
"""
owner-scoped 注册表基类 —— 抽取自 ``app/core/sso.py`` 的 ``AuthProviderRegistry``，
供主认证 provider 与 MFA 因子两条车道复用，避免重复实现 register/unregister/碰撞检测逻辑。

子类约定（最小面）：
  - ``_id_of(item) -> str``            ：取注册键（如 provider_id / factor_id）；
  - ``_validate(item) -> (bool, list)``：契约校验，返回 (是否通过, 失败原因列表)；
  - ``_sort_key(item) -> Any``         ：可选，``all()`` 有序遍历的排序键（默认保持注册顺序）。
"""
from threading import RLock
from typing import Any, Dict, List, NamedTuple, Optional, Tuple


class _Entry(NamedTuple):
    item: Any
    owner: Optional[str]                            # 注册来源插件 id；None 表示内建


class OwnerScopedRegistry:
    """按注册键单索引、带 owner 以便按插件卸载的线程安全注册表（仿 ``AuthProviderRegistry``）。"""

    def __init__(self) -> None:
        self._registry: Dict[str, _Entry] = {}
        self._lock = RLock()

    # --- 子类需覆盖 ---
    def _id_of(self, item: Any) -> str:
        raise NotImplementedError

    def _validate(self, item: Any) -> Tuple[bool, List[str]]:
        raise NotImplementedError

    def _sort_key(self, item: Any) -> Any:          # 默认不排序（dict 保持注册顺序）
        return 0

    # --- 公共 API ---
    def register(self, item: Any, owner: Optional[str]) -> Tuple[bool, str]:
        """注册一个对象：先过契约校验，再做注册键碰撞检测（不同 owner 占用同键则拒绝）。
        返回 (是否成功, 失败原因)。同一 owner 重复注册同键视为幂等覆盖。"""
        ok, reasons = self._validate(item)
        if not ok:
            return False, "；".join(reasons)
        key = self._id_of(item)
        with self._lock:
            existing = self._registry.get(key)
            if existing is not None and existing.owner != owner:
                return False, f"注册键冲突：{key} 已由 {existing.owner or '内建'} 注册"
            self._registry[key] = _Entry(item, owner)
        return True, ""

    def unregister(self, owner: Optional[str]) -> None:
        """卸载某 owner（插件）注册的全部对象。"""
        with self._lock:
            for key in [k for k, e in self._registry.items() if e.owner == owner]:
                self._registry.pop(key, None)

    def get(self, key: str) -> Optional[Any]:
        """按注册键取对象，不存在返回 None。"""
        with self._lock:
            entry = self._registry.get(key)
            return entry.item if entry else None

    def ids(self) -> List[str]:
        """已注册的全部键。"""
        with self._lock:
            return list(self._registry.keys())

    def all(self) -> List[Any]:
        """已注册的全部对象，按 ``_sort_key`` 升序（默认保持注册顺序）。"""
        with self._lock:
            items = [e.item for e in self._registry.values()]
        return sorted(items, key=self._sort_key)
