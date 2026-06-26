# -*- coding: utf-8 -*-
"""
内建 MFA 因子：``OtpFactor`` / ``PasskeyFactor`` —— 1:1 复现现 ``app/chain/user.py._verify_mfa`` 的行为。

与插件因子一致的 MFA 因子构件（鸭子类型），但"是否已注册 / 如何验证"通过注入的 callable 提供：
生产侧由装配桥（``auth._builtin_factor_steps``）绑定到已解析的 ``User``；单测注入 fake，保持 db-free。

行为锚点（``_verify_mfa`` user.py:177-218，由 PR2 黄金矩阵守护）：
  - **OTP 优先**：``is_otp`` 时以 OTP 码判定 allow/deny（priority 更小，先验证）；
  - **PassKey 延后**：仅 PassKey 时本登录流程返回 ``challenge_required``（真正验证在独立 passkey 端点）。
"""
from typing import Callable, List, Optional

from app.core.auth.types import MfaChallengeHint, MfaSubmission, MfaUserRef
from app.core.auth.outcome import MfaFactorResult

# 内建因子优先级：OTP 先于 PassKey，复现 _verify_mfa 的 is_otp 优先
_OTP_PRIORITY = 10
_PASSKEY_PRIORITY = 20


class OtpFactor:
    """TOTP 动态口令因子（提交即验的持有因子）。"""

    factor_id = "otp"
    factor_kind = "possession"
    display_name = "动态口令 (OTP)"
    priority = _OTP_PRIORITY

    def __init__(self, is_enrolled: Callable[[MfaUserRef], bool],
                 verify: Callable[[MfaUserRef, str], bool]) -> None:
        self._is_enrolled = is_enrolled
        self._verify = verify

    def is_enrolled(self, user_ref: MfaUserRef) -> bool:
        return bool(self._is_enrolled(user_ref))

    def verify(self, user_ref: MfaUserRef, submission: MfaSubmission) -> MfaFactorResult:
        if submission.code and self._verify(user_ref, submission.code):
            return MfaFactorResult(status="allow")
        return MfaFactorResult(status="deny")

    def challenge_hint(self, user_ref: MfaUserRef) -> Optional[MfaChallengeHint]:
        if not self.is_enrolled(user_ref):
            return None
        return MfaChallengeHint(factor_id=self.factor_id, factor_kind=self.factor_kind,
                                display_name=self.display_name)


class PasskeyFactor:
    """WebAuthn / 通行密钥因子。验证在独立 passkey 端点完成，本登录流程内返回 ``challenge_required``。"""

    factor_id = "passkey"
    factor_kind = "biometric"
    display_name = "通行密钥 (PassKey)"
    priority = _PASSKEY_PRIORITY

    def __init__(self, is_enrolled: Callable[[MfaUserRef], bool]) -> None:
        self._is_enrolled = is_enrolled

    def is_enrolled(self, user_ref: MfaUserRef) -> bool:
        return bool(self._is_enrolled(user_ref))

    def verify(self, user_ref: MfaUserRef, submission: MfaSubmission) -> MfaFactorResult:
        # PassKey 不经登录表单的码验证；交由独立端点，故此处声明需走挑战
        return MfaFactorResult(status="challenge_required")

    def challenge_hint(self, user_ref: MfaUserRef) -> Optional[MfaChallengeHint]:
        if not self.is_enrolled(user_ref):
            return None
        return MfaChallengeHint(factor_id=self.factor_id, factor_kind=self.factor_kind,
                                display_name=self.display_name)


def build_builtin_factors(*, is_otp_enrolled: Callable[[MfaUserRef], bool],
                          verify_otp: Callable[[MfaUserRef, str], bool],
                          has_passkey: Callable[[MfaUserRef], bool]) -> List:
    """构造内建因子实例（生产侧由编排器绑定到已解析 ``User``；单测注入 fake）。"""
    return [
        OtpFactor(is_enrolled=is_otp_enrolled, verify=verify_otp),
        PasskeyFactor(is_enrolled=has_passkey),
    ]
