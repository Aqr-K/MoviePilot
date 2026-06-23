# -*- coding: utf-8 -*-
"""
认证编排器 —— MFA 评估（PR2）。``resolve_identity`` 在 PR4 落地。

``evaluate_mfa`` 按 ``priority`` 升序遍历因子，折叠为统一 ``AuthResult``；
PR3 将以它替换 ``app/chain/user.py._verify_mfa``，并把 ``AuthResult`` 折叠回
``(True / "MFA_REQUIRED" / False)`` 以保持 v2 外部契约不变。
"""
from typing import Iterable, Optional

from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
from app.core.auth.outcome import AuthResult


def evaluate_mfa(user_ref: MfaUserRef, submission: Optional[MfaSubmission],
                 factors: Iterable) -> AuthResult:
    """评估 MFA（语义复现 ``_verify_mfa``）：

    - 无已注册因子 → ``success``；
    - 有因子但无有效提交 → ``mfa_required``（列出可用因子 id）；
    - 有提交 → 按 priority 依次验证：首个 ``allow``→``success`` / ``deny``→``failure``；
      若无因子能同步验证（如仅 PassKey）→ ``mfa_required``（前端走对应端点）。
    """
    ordered = sorted(factors, key=lambda f: getattr(f, "priority", 0))
    enrolled = [f for f in ordered if f.is_enrolled(user_ref)]
    if not enrolled:
        return AuthResult(kind="success")
    has_submission = bool(submission and (submission.code or submission.response))
    if not has_submission:
        return AuthResult(kind="mfa_required",
                          factors_available=[f.factor_id for f in enrolled])
    for factor in enrolled:
        result = factor.verify(user_ref, submission)
        if result.status == "allow":
            return AuthResult(kind="success")
        if result.status == "deny":
            return AuthResult(kind="failure")
        # not_enrolled / challenge_required → 尝试下一个因子
    return AuthResult(kind="mfa_required",
                      factors_available=[f.factor_id for f in enrolled])
