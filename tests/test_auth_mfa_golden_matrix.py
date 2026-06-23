# -*- coding: utf-8 -*-
"""
PR2 黄金矩阵：断言 ``orchestrator.evaluate_mfa`` + 内建因子 与现 ``UserChain._verify_mfa``
在 ``{is_otp × has_passkey × code(none/valid/invalid)}`` 全 12 格矩阵上**等价**。

oracle 直接调用真实 ``_verify_mfa``（monkeypatch ``PassKey``/``OtpUtils``），保证是**特征比对**
而非转写。现有编排测试整体 mock 掉 ``_verify_mfa``，无法守护 PR3 的折叠回归，故本测试是
PR3 替换 ``_verify_mfa`` 的独立护栏（oracle）。
"""
import itertools
import types

import pytest

from app.chain.user import UserChain
from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
from app.service.auth.builtin_factors import build_builtin_factors
from app.service.auth.orchestrator import evaluate_mfa

# AuthResult.kind → 现 _verify_mfa 的三值返回
_KIND_TO_LEGACY = {"success": True, "mfa_required": "MFA_REQUIRED", "failure": False}


@pytest.mark.parametrize(
    "is_otp,has_passkey,code_state",
    list(itertools.product([True, False], [True, False], ["none", "valid", "invalid"])),
)
def test_evaluate_mfa_matches_legacy(monkeypatch, is_otp, has_passkey, code_state):
    import app.db.models.passkey as passkey_mod
    import app.utils.otp as otp_mod

    otp_valid = code_state == "valid"
    code = None if code_state == "none" else "123456"

    # --- oracle：真实 _verify_mfa（注入 PassKey 枚举与 OTP 校验结果） ---
    monkeypatch.setattr(
        passkey_mod.PassKey, "get_by_user_id",
        staticmethod(lambda db=None, user_id=None: ([object()] if has_passkey else [])),
    )
    monkeypatch.setattr(
        otp_mod.OtpUtils, "check",
        staticmethod(lambda secret, password: otp_valid),
    )
    fake_user = types.SimpleNamespace(id=1, name="admin", is_otp=is_otp, otp_secret="SECRET")
    legacy = UserChain._verify_mfa(fake_user, code)

    # --- 新实现：evaluate_mfa + 内建因子（注入同样的 fake 判定） ---
    factors = build_builtin_factors(
        is_otp_enrolled=lambda ref: is_otp,
        verify_otp=lambda ref, c: otp_valid,
        has_passkey=lambda ref: has_passkey,
    )
    ref = MfaUserRef(user_id=1, username="admin")
    submission = MfaSubmission(code=code)
    new = evaluate_mfa(ref, submission, factors)

    assert _KIND_TO_LEGACY[new.kind] == legacy, (
        f"mismatch at is_otp={is_otp} has_passkey={has_passkey} code={code_state}: "
        f"legacy={legacy!r} new_kind={new.kind!r}"
    )
