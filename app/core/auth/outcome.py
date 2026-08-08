# -*- coding: utf-8 -*-
"""
认证编排的类型化结果 —— 替换原 ``app/chain/user.py`` 的 ``_AuthOutcome``（v3 内部结构）。

设计要点：
  - 全部为 frozen dataclass（不可变，避免认证链路中途被改写）；
  - ``CredentialOutcome.mfa_already_satisfied`` 承载"联合认证已满足 MFA"的信号，住在 v3 自有结果
    对象里，**绝不**回灌进冻结的 ``AuthCredentials``（其无 ``extra`` 字段且校验器拒绝多余字段）；
  - ``AuthResult`` 是编排器/登录端点对外的统一结果，可直接序列化为结构化登录响应。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.db.models.user import User


@dataclass(frozen=True)
class CredentialOutcome:
    """主认证 provider 的校验结果。``status`` 语义：

    - ``"success"`` ：校验通过，``username`` 指向应登录的本地/外部身份；
    - ``"reject"``  ：这是我该处理的凭证，但校验失败（如密码错）；
    - ``"error"``   ：我处理时发生错误（如外部服务不可达）；
    - ``"not_mine"``：这不是我该处理的凭证，应交给下一个 provider。
    """

    status: Literal["success", "reject", "error", "not_mine"]
    username: Optional[str] = None
    display_name: Optional[str] = None
    avatar: Optional[str] = None
    mfa_already_satisfied: bool = False
    error_code: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MfaFactorResult:
    """单个 MFA 因子的判定结果。``status`` 语义：

    - ``"allow"``             ：该因子验证通过；
    - ``"deny"``              ：该因子验证失败；
    - ``"not_enrolled"``      ：用户未注册该因子（不参与判定）；
    - ``"challenge_required"``：需先下发挑战（带外因子，如 SMS/Email），``challenge`` 为提示载荷。
    """

    status: Literal["allow", "deny", "not_enrolled", "challenge_required"]
    challenge: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ResolvedIdentity:
    """主认证解析出的已认证身份（尚未走 MFA）。``apply_mfa`` 为 False 表示联合方已断言 MFA 已满足。"""

    user: "User"
    apply_mfa: bool = True


@dataclass(frozen=True)
class AuthResult:
    """编排器/登录端点对外的统一结果。``kind`` 语义：

    - ``"success"``     ：认证完成，``user`` 可签发 token；
    - ``"mfa_required"``：需第二因子，``factors_available`` 列出可用因子 id；
    - ``"challenge"``   ：需先完成一次挑战-应答，``challenge`` 为载荷；
    - ``"failure"``     ：认证失败，``error`` 为（脱敏后）原因。
    """

    kind: Literal["success", "mfa_required", "challenge", "failure"]
    user: Optional["User"] = None
    factors_available: Optional[List[str]] = None
    challenge: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
