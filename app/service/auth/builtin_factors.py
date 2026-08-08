# -*- coding: utf-8 -*-
"""
内建 MFA 因子：``OtpFactor`` —— 1:1 复现现 ``app/chain/user.py._verify_mfa`` 的行为。

与插件因子一致的 MFA 因子构件（鸭子类型），但"是否已注册 / 如何验证"通过注入的 callable 提供：
生产侧由装配桥（``auth._builtin_factor_steps``）绑定到已解析的 ``User``；单测注入 fake，保持 db-free。

行为锚点（``_verify_mfa`` user.py:177-218，由引擎集成测试与安全回归套件守护）：
  - **OTP**：``is_otp`` 时以提交的动态码判定 allow/deny。

通行密钥（PassKey）是**主认证方式**（``PasskeyLoginStep`` / ``/mfa/passkey/authenticate/finish``），
不是第二因子：其断言校验须在铸 Token 前完成，无法由密码登录后的因子阶段承载。
"""
from typing import Callable, List, Optional

from app.core.auth.types import MfaChallengeHint, MfaSubmission, MfaUserRef
from app.core.auth.outcome import MfaFactorResult

# 内建因子优先级（数值越小越先验证）
_OTP_PRIORITY = 10


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


def build_builtin_factors(*, is_otp_enrolled: Callable[[MfaUserRef], bool],
                          verify_otp: Callable[[MfaUserRef, str], bool]) -> List:
    """构造内建因子实例（生产侧由编排器绑定到已解析 ``User``；单测注入 fake）。

    :param is_otp_enrolled: 判定该用户是否已启用 OTP
    :param verify_otp: 校验该用户提交的 OTP 动态码
    :return: 内建 MFA 因子构件列表
    """
    return [
        OtpFactor(is_enrolled=is_otp_enrolled, verify=verify_otp),
    ]
