# -*- coding: utf-8 -*-
"""
SSO（外部 IdP 单点登录）框架能力 —— db-free 核心。

把每个 SSO 插件原本要各自重复实现的样板（G3）下沉为框架能力：
  - CSRF ``state`` 的签发/单次校验（``RedirectStateStore``）；
  - 登录提供方的注册/路由（``AuthProviderRegistry``，按 ``provider_id`` 单索引、带 owner）；
  - 提供方契约校验（``verify_auth_provider_contract``）。

插件只需交出 IdP 特定的两件事（见 ``IAuthProvider``）：``authorize_url`` 与 ``fetch_identity``；
用户解析/建号（碰 db）与 HTTP 端点编排在更上层（helper / api），本模块保持 **db-free**
（延续 auth_bridge 去 db 的方向，不新增 core→db 边）。
"""
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from app.core.auth.identifiers import is_valid_identifier
from app.core.auth.registry import OwnerScopedRegistry
from app.core.challenge_store import ChallengeStore


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
    if not is_valid_identifier(pid):
        reasons.append("provider_id 必须为 1–32 位字母、数字或连字符（不含下划线/路径分隔符）")
    for attr in ("provider_name", "provider_icon"):
        if not isinstance(getattr(provider, attr, None), str):
            reasons.append(f"{attr} 必须为字符串")
    for meth in ("authorize_url", "fetch_identity"):
        if not callable(getattr(provider, meth, None)):
            reasons.append(f"须实现 {meth} 方法")
    return (not reasons), reasons


class RedirectStateStore:
    """
    OAuth ``state`` 短时一次性存储（CSRF 防护）：签发时写、回调时取（取即销毁）。

    复用 ``ChallengeStore``（内存 + 锁 + TTL）承载存储语义，本类只负责"签发不可猜测随机串 +
    把消费结果折叠为布尔"。state 无 payload，故消费判定用 ``is not None``（空 payload 仍合法）。
    """

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._store = ChallengeStore(ttl_seconds=ttl_seconds)

    def issue(self, flow_token: str, provider_id: str) -> str:
        """生成并登记一个新 state（携带 flow_token + provider_id），返回不可猜测的随机串。"""
        state = secrets.token_urlsafe(24)
        self._store.put(state, {"flow_token": flow_token, "provider_id": provider_id})
        return state

    def consume(self, state: Optional[str]) -> Optional[Dict[str, str]]:
        """取用并销毁一个 state（原子）；返回 {"flow_token", "provider_id"}，未知/过期/已用返回 None。"""
        if not state:
            return None
        payload = self._store.consume(state)
        if payload is None:
            return None
        return {"flow_token": payload["flow_token"], "provider_id": payload["provider_id"]}


class AuthProviderRegistry(OwnerScopedRegistry):
    """
    SSO 登录提供方注册表：按 ``provider_id`` 单索引、带 owner 以便按插件卸载。

    实现为 ``OwnerScopedRegistry`` 子类（与主认证 provider / MFA 因子注册表共用 register/unregister/
    碰撞检测逻辑）；只声明取键与契约校验。无 priority 概念，故不覆写 ``_sort_key``，``all()`` 保持注册顺序。
    """

    def _id_of(self, item: Any) -> str:
        return item.provider_id

    def _validate(self, item: Any) -> Tuple[bool, List[str]]:
        return verify_auth_provider_contract(item)

    def provider_ids(self) -> List[str]:
        """已注册的 provider_id 列表（``ids()`` 的语义化别名）。"""
        return self.ids()


# 模块级单例：state 与提供方注册表均需跨请求/跨插件存活
_STATE_STORE = RedirectStateStore()
_REGISTRY = AuthProviderRegistry()


def issue_state(flow_token: str, provider_id: str) -> str:
    """签发一个一次性 CSRF state，携带 flow_token 与 provider_id。"""
    return _STATE_STORE.issue(flow_token=flow_token, provider_id=provider_id)


def consume_state(state: Optional[str]) -> Optional[Dict[str, str]]:
    """原子取用并销毁一个 CSRF state；返回 {"flow_token", "provider_id"}，否则 None。"""
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
