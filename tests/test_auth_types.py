# -*- coding: utf-8 -*-
"""
Task 2 — 共享值类型迁入 types.py

验证四个冻结数据类可直接从 app.core.auth.types 导入并实例化。
"""
from app.core.auth.types import CredentialRequest, MfaUserRef, MfaSubmission, MfaChallengeHint


def test_value_types_from_types():
    assert CredentialRequest(grant_type="password").grant_type == "password"
    assert MfaUserRef(user_id=1, username="a").username == "a"
    assert MfaSubmission().code is None
    assert MfaChallengeHint(factor_id="otp", factor_kind="possession", display_name="OTP")
