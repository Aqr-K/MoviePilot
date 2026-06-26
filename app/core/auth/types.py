# -*- coding: utf-8 -*-
"""认证流程在各层间传递的共享值类型（db-free 冻结数据类）。"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class CredentialRequest:
    """主认证输入 DTO：由编排器从 ``AuthCredentials`` 构造，插件特定字段放入 ``extra``。"""

    grant_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    code: Optional[str] = None
    mfa_code: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MfaUserRef:
    """传给因子的轻量用户引用（仅身份，不含 otp_secret 等密钥；需要更多状态的因子自行查库）。"""

    user_id: Any
    username: str


@dataclass(frozen=True)
class MfaSubmission:
    """用户对某次 MFA 的提交。``factor_id`` 为空表示单码提交（对应 ``otp_password`` 路径）。"""

    factor_id: Optional[str] = None
    code: Optional[str] = None
    response: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MfaChallengeHint:
    """因子对外暴露的"下一步如何应答"提示（前端据此渲染；带外因子可含已下发挑战）。"""

    factor_id: str
    factor_kind: str
    display_name: str
    challenge: Optional[Dict[str, Any]] = None
