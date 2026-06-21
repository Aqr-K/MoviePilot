# -*- coding: utf-8 -*-
"""
SSO（外部 IdP 单点登录）框架能力 —— db-free 核心。

把每个 SSO 插件原本要各自重复实现的样板（G3）下沉为框架能力：
  - CSRF ``state`` 的签发/单次校验（``SsoStateStore``）；
  - 登录提供方的注册/路由（``AuthProviderRegistry``，按 ``provider_id`` 单索引、带 owner）；
  - 提供方契约校验（``verify_auth_provider_contract``）。

插件只需交出 IdP 特定的两件事（见 ``IAuthProvider``）：``authorize_url`` 与 ``fetch_identity``；
用户解析/建号（碰 db）与 HTTP 端点编排在更上层（helper / api），本模块保持 **db-free**
（延续 auth_bridge 去 db 的方向，不新增 core→db 边）。
"""
import re
import secrets
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Dict, List, NamedTuple, Optional, Protocol, Tuple, runtime_checkable

# provider_id 合法字符集：字母数字与连字符，1–32 位。禁用下划线等分隔符——provider_id 会进入本地用户名
# ``sso_{provider_id}_{外部用户名}`` 与回调 URL 路径片段，禁分隔符可数学上杜绝跨提供方撞名与路径注入。
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")


@dataclass
class AuthProviderIdentity:
    """提供方校验成功后返回的外部身份（与本地用户解耦，由上层映射为本地用户）。"""

    subject: str                                   # IdP 侧稳定用户标识
    username: str                                  # IdP 侧用户名（上层会加命名空间前缀）
    avatar: Optional[str] = None
    display_name: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IAuthProvider(Protocol):
    """
    SSO 登录提供方契约（插件只实现 IdP 特定的最小面）。

    数据属性：
      - provider_id：唯一标识（如 "github"），用于路由与去重；
      - provider_name / provider_icon：登录页入口展示。
    方法：
      - authorize_url(state, redirect_uri)：构造 IdP 授权页 URL（框架负责签发 state、拼回调）；
      - fetch_identity(code, redirect_uri)：用授权码换取外部身份，失败返回 None。
    """

    provider_id: str
    provider_name: str
    provider_icon: str

    def authorize_url(self, state: str, redirect_uri: str) -> str: ...

    def fetch_identity(self, code: str, redirect_uri: str) -> Optional[AuthProviderIdentity]: ...


def verify_auth_provider_contract(provider: Any) -> Tuple[bool, List[str]]:
    """
    校验对象是否满足 ``IAuthProvider`` 契约。返回 (是否通过, 失败原因列表)。

    不依赖 isinstance（runtime_checkable 对数据属性的判定随版本而异），做显式检查以给出清晰原因。
    """
    reasons: List[str] = []
    pid = getattr(provider, "provider_id", None)
    if not isinstance(pid, str) or not _PROVIDER_ID_RE.match(pid):
        reasons.append("provider_id 必须为 1–32 位字母、数字或连字符（不含下划线/路径分隔符）")
    for attr in ("provider_name", "provider_icon"):
        if not isinstance(getattr(provider, attr, None), str):
            reasons.append(f"{attr} 必须为字符串")
    for meth in ("authorize_url", "fetch_identity"):
        if not callable(getattr(provider, meth, None)):
            reasons.append(f"须实现 {meth} 方法")
    return (not reasons), reasons


class SsoStateStore:
    """
    OAuth ``state`` 短时一次性存储（CSRF 防护）：内存 + 锁 + TTL，签发时写、回调时取（取即销毁）。
    """

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._ttl = ttl_seconds
        self._states: Dict[str, float] = {}
        self._lock = RLock()

    def issue(self) -> str:
        """生成并登记一个新 state，返回不可猜测的随机串。"""
        state = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._cleanup(now)
            self._states[state] = now
        return state

    def consume(self, state: Optional[str]) -> bool:
        """取用一个 state：存在且未过期返回 True（并删除），否则 False（单次有效）。"""
        if not state:
            return False
        now = time.time()
        with self._lock:
            issued_at = self._states.pop(state, None)
            self._cleanup(now)
        return bool(issued_at) and (now - issued_at) <= self._ttl

    def _cleanup(self, now: float) -> None:
        expired = [s for s, t in self._states.items() if now - t > self._ttl]
        for s in expired:
            self._states.pop(s, None)


class _Entry(NamedTuple):
    provider: Any
    owner: Optional[str]                            # 注册来源插件 id；None 表示内建


class AuthProviderRegistry:
    """
    SSO 登录提供方注册表：按 ``provider_id`` 单索引（仿 storage_registry），带 owner 以便按插件卸载。
    """

    def __init__(self) -> None:
        self._registry: Dict[str, _Entry] = {}
        self._lock = RLock()

    def register(self, provider: Any, owner: Optional[str]) -> Tuple[bool, str]:
        """
        注册一个提供方：先过契约校验，再做 provider_id 碰撞检测（不同 owner 占用同 id 则拒绝）。
        返回 (是否成功, 失败原因)。同一 owner 重复注册同 id 视为幂等覆盖。
        """
        ok, reasons = verify_auth_provider_contract(provider)
        if not ok:
            return False, "；".join(reasons)
        pid = provider.provider_id
        with self._lock:
            existing = self._registry.get(pid)
            if existing is not None and existing.owner != owner:
                return False, f"provider_id 冲突：{pid} 已由 {existing.owner or '内建'} 注册"
            self._registry[pid] = _Entry(provider, owner)
        return True, ""

    def unregister(self, owner: Optional[str]) -> None:
        """卸载某 owner（插件）注册的全部提供方。"""
        with self._lock:
            for pid in [k for k, e in self._registry.items() if e.owner == owner]:
                self._registry.pop(pid, None)

    def get(self, provider_id: str) -> Optional[Any]:
        """按 provider_id 取提供方，不存在返回 None。"""
        with self._lock:
            entry = self._registry.get(provider_id)
            return entry.provider if entry else None

    def provider_ids(self) -> List[str]:
        """已注册的 provider_id 列表。"""
        with self._lock:
            return list(self._registry.keys())

    def all(self) -> List[Any]:
        """已注册的全部提供方对象。"""
        with self._lock:
            return [e.provider for e in self._registry.values()]


# 模块级单例：state 与提供方注册表均需跨请求/跨插件存活
_STATE_STORE = SsoStateStore()
_REGISTRY = AuthProviderRegistry()


def issue_state() -> str:
    """签发一个一次性 CSRF state。"""
    return _STATE_STORE.issue()


def consume_state(state: Optional[str]) -> bool:
    """校验并消费一个 CSRF state（单次有效）。"""
    return _STATE_STORE.consume(state)


def register_auth_provider(provider: Any, owner: Optional[str]) -> Tuple[bool, str]:
    """注册一个 SSO 登录提供方（契约校验 + provider_id 碰撞检测）。"""
    return _REGISTRY.register(provider, owner)


def unregister_auth_providers(owner: Optional[str]) -> None:
    """卸载某 owner（插件）注册的全部提供方。"""
    _REGISTRY.unregister(owner)


def get_auth_provider(provider_id: str) -> Optional[Any]:
    """按 provider_id 取已注册提供方。"""
    return _REGISTRY.get(provider_id)


def registered_provider_ids() -> List[str]:
    """已注册的 provider_id 列表。"""
    return _REGISTRY.provider_ids()


def all_auth_providers() -> List[Any]:
    """已注册的全部提供方对象。"""
    return _REGISTRY.all()
