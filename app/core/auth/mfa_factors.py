# -*- coding: utf-8 -*-
"""
MFA 因子契约 + 注册表（db-free）。

第二因子（"你额外拥有/是什么"）：TOTP/HOTP、WebAuthn/PassKey、SMS/Email OTP、推送、备份码、
生物（经 WebAuthn 中介）、行为/风控信号等。内建 OTP、PassKey 因子在 PR2 落地（1:1 复现现 _verify_mfa）。

因子保持 db-free：core 只持有契约与注册表；需要查库的因子（如 PassKey 读凭证表）自行查询，
通过传入的轻量 ``MfaUserRef``（仅身份引用，不含密钥）定位用户。
"""
from dataclasses import field  # noqa: F401 — kept for indirect compat
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from app.core.auth.identifiers import is_valid_identifier
from app.core.auth.outcome import MfaFactorResult
from app.core.auth.registry import OwnerScopedRegistry
from app.core.auth.types import MfaChallengeHint, MfaSubmission, MfaUserRef  # re-export (T13 时随契约一并删)

_MFA_FACTOR_KINDS = {"knowledge", "possession", "biometric"}


@runtime_checkable
class IMfaFactor(Protocol):
    """MFA 因子契约。

    数据属性：``factor_id``（唯一）、``factor_kind``（见 ``_MFA_FACTOR_KINDS``）、``display_name``、
    ``priority``（升序）。
    方法：
      - ``is_enrolled(user_ref)``        ：用户是否已注册该因子；
      - ``verify(user_ref, submission)`` ：验证提交，返回 ``MfaFactorResult``（永不抛异常）；
      - ``challenge_hint(user_ref)``     ：返回应答提示（无则 None；带外因子可在此下发挑战）。
    """

    factor_id: str
    factor_kind: str
    display_name: str
    priority: int

    def is_enrolled(self, user_ref: "MfaUserRef") -> bool: ...

    def verify(self, user_ref: "MfaUserRef", submission: "MfaSubmission") -> MfaFactorResult: ...

    def challenge_hint(self, user_ref: "MfaUserRef") -> Optional["MfaChallengeHint"]: ...


def verify_mfa_factor_contract(factor: Any) -> Tuple[bool, List[str]]:
    """校验对象是否满足 ``IMfaFactor`` 契约。返回 (是否通过, 失败原因列表)。"""
    reasons: List[str] = []
    fid = getattr(factor, "factor_id", None)
    if not is_valid_identifier(fid):
        reasons.append("factor_id 必须为 1–32 位字母、数字或连字符")
    if getattr(factor, "factor_kind", None) not in _MFA_FACTOR_KINDS:
        reasons.append(f"factor_kind 必须为 {sorted(_MFA_FACTOR_KINDS)} 之一")
    if not isinstance(getattr(factor, "display_name", None), str):
        reasons.append("display_name 必须为字符串")
    priority = getattr(factor, "priority", None)
    if not isinstance(priority, int) or isinstance(priority, bool):
        reasons.append("priority 必须为整数")
    for meth in ("is_enrolled", "verify", "challenge_hint"):
        if not callable(getattr(factor, meth, None)):
            reasons.append(f"须实现 {meth} 方法")
    return (not reasons), reasons


class MfaFactorRegistry(OwnerScopedRegistry):
    """MFA 因子注册表：按 ``factor_id`` 单索引、带 owner、按 ``priority`` 升序遍历。"""

    def _id_of(self, item: Any) -> str:
        return item.factor_id

    def _validate(self, item: Any) -> Tuple[bool, List[str]]:
        return verify_mfa_factor_contract(item)

    def _sort_key(self, item: Any) -> Any:
        return getattr(item, "priority", 0)


# 模块级单例 + 自由函数
_REGISTRY = MfaFactorRegistry()


def register_mfa_factor(factor: Any, owner: Optional[str]) -> Tuple[bool, str]:
    """注册一个 MFA 因子（契约校验 + factor_id 碰撞检测）。"""
    return _REGISTRY.register(factor, owner)


def unregister_mfa_factors(owner: Optional[str]) -> None:
    """卸载某 owner（插件）注册的全部 MFA 因子。"""
    _REGISTRY.unregister(owner)


def get_mfa_factor(factor_id: str) -> Optional[Any]:
    """按 factor_id 取已注册因子。"""
    return _REGISTRY.get(factor_id)


def registered_mfa_factor_ids() -> List[str]:
    """已注册的 factor_id 列表。"""
    return _REGISTRY.ids()


def all_mfa_factors() -> List[Any]:
    """全部已注册因子，按 priority 升序。"""
    return _REGISTRY.all()
