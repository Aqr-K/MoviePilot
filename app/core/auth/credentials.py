# -*- coding: utf-8 -*-
"""
主认证 provider 契约 + 注册表（db-free）。

"主认证"= 用什么证明身份的第一道关：本地密码、LDAP/AD/RADIUS 目录绑定、
OIDC-ROPC/SAML-ECP 等非重定向联合认证、passwordless 等。插件交出一个 ``ICredentialProvider``，
框架按 ``priority`` 升序依次询问，首个返回 ``status="success"`` 者胜出（见 orchestrator，PR3/PR4）。

与 SSO 重定向车道（``app/core/sso.py`` 的 ``IAuthProvider``）的分工：
  - 重定向（浏览器跳到 IdP 再回调）→ ``IAuthProvider``；
  - 直接用凭证换身份（无浏览器重定向）→ 本模块 ``ICredentialProvider``。
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from app.core.auth.outcome import CredentialOutcome
from app.core.auth.registry import OwnerScopedRegistry

# provider_id 合法字符集：与 sso.py 对齐（字母数字与连字符，1–32 位，禁分隔符防撞名/路径注入）
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9\-]{1,32}$")
# 因子大类：对齐认证分类（知识/持有 + 本地目录/非重定向联合）
_FACTOR_KINDS = {"knowledge", "possession", "directory", "federated_direct"}


@dataclass(frozen=True)
class CredentialRequest:
    """主认证输入（v3 自有 DTO，由编排器从 ``AuthCredentials`` 构造；插件特定字段放 ``extra``）。"""

    grant_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    code: Optional[str] = None
    mfa_code: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ICredentialProvider(Protocol):
    """主认证 provider 契约（插件实现最小面）。

    数据属性：
      - ``provider_id``：唯一标识（路由/去重/日志）；
      - ``factor_kind``：因子大类，取值见 ``_FACTOR_KINDS``；
      - ``priority``   ：询问顺序，升序；内建本地密码 = 0，插件应 > 0。
    方法：
      - ``applies_to(req)``        ：本 provider 是否应处理该请求（快速短路，不做重活）；
      - ``verify_credentials(req)``：校验凭证，返回 ``CredentialOutcome``（永不抛异常，失败用 status 表达）。
    """

    provider_id: str
    factor_kind: str
    priority: int

    def applies_to(self, req: "CredentialRequest") -> bool: ...

    def verify_credentials(self, req: "CredentialRequest") -> CredentialOutcome: ...


def verify_credential_provider_contract(provider: Any) -> Tuple[bool, List[str]]:
    """校验对象是否满足 ``ICredentialProvider`` 契约。返回 (是否通过, 失败原因列表)。

    不依赖 isinstance（runtime_checkable 对数据属性判定随版本而异），做显式检查以给出清晰原因。
    """
    reasons: List[str] = []
    pid = getattr(provider, "provider_id", None)
    if not isinstance(pid, str) or not _PROVIDER_ID_RE.match(pid):
        reasons.append("provider_id 必须为 1–32 位字母、数字或连字符（不含下划线/路径分隔符）")
    if getattr(provider, "factor_kind", None) not in _FACTOR_KINDS:
        reasons.append(f"factor_kind 必须为 {sorted(_FACTOR_KINDS)} 之一")
    priority = getattr(provider, "priority", None)
    if not isinstance(priority, int) or isinstance(priority, bool):
        reasons.append("priority 必须为整数")
    for meth in ("applies_to", "verify_credentials"):
        if not callable(getattr(provider, meth, None)):
            reasons.append(f"须实现 {meth} 方法")
    return (not reasons), reasons


class CredentialProviderRegistry(OwnerScopedRegistry):
    """主认证 provider 注册表：按 ``provider_id`` 单索引、带 owner、按 ``priority`` 升序遍历。"""

    def _id_of(self, item: Any) -> str:
        return item.provider_id

    def _validate(self, item: Any) -> Tuple[bool, List[str]]:
        return verify_credential_provider_contract(item)

    def _sort_key(self, item: Any) -> Any:
        return getattr(item, "priority", 0)


# 模块级单例 + 自由函数（跨请求/跨插件存活，仿 sso.py）
_REGISTRY = CredentialProviderRegistry()


def register_credential_provider(provider: Any, owner: Optional[str]) -> Tuple[bool, str]:
    """注册一个主认证 provider（契约校验 + provider_id 碰撞检测）。"""
    return _REGISTRY.register(provider, owner)


def unregister_credential_providers(owner: Optional[str]) -> None:
    """卸载某 owner（插件）注册的全部主认证 provider。"""
    _REGISTRY.unregister(owner)


def get_credential_provider(provider_id: str) -> Optional[Any]:
    """按 provider_id 取已注册 provider。"""
    return _REGISTRY.get(provider_id)


def registered_credential_provider_ids() -> List[str]:
    """已注册的 provider_id 列表。"""
    return _REGISTRY.ids()


def all_credential_providers() -> List[Any]:
    """全部已注册 provider，按 priority 升序。"""
    return _REGISTRY.all()
