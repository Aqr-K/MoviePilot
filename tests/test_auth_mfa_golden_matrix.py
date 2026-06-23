# -*- coding: utf-8 -*-
"""
PR2/PR3 黄金矩阵：在 ``{is_otp × has_passkey × code(none/valid/invalid)}`` 全 12 格上，断言
  (a) ``orchestrator.evaluate_mfa`` + 内建因子，与
  (b) PR3 改写后委托式 ``UserChain._verify_mfa``，
均等于一份**冻结真值表**（``user.py:177-218`` 替换前语义的转写）。

为何用冻结表而非"活的 ``_verify_mfa``"：PR3 把 ``_verify_mfa`` 改为委托 ``evaluate_mfa`` 后，
二者代码路径合一，若仍以活的 ``_verify_mfa`` 作 oracle 会退化为自比对（恒真）。冻结表是独立
oracle，同时守护 evaluate_mfa 与 _verify_mfa（含其三值折叠）。现有编排测试整体 mock 掉
``_verify_mfa``，无法守护本折叠，故本测试是该替换的关键护栏。
"""
import itertools
import types

import pytest

from app.chain.user import UserChain
from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
from app.service.auth.builtin_factors import build_builtin_factors
from app.service.auth.orchestrator import evaluate_mfa

_KIND_TO_LEGACY = {"success": True, "mfa_required": "MFA_REQUIRED", "failure": False}


def _expected_legacy(is_otp, has_passkey, code_state):
    """冻结：``user.py:177-218``（替换前）的三值真值表。"""
    if not is_otp and not has_passkey:
        return True
    if code_state == "none":
        return "MFA_REQUIRED"
    if is_otp:
        return True if code_state == "valid" else False
    # 未启用 OTP 但有 PassKey 且提供了码：码被忽略，仍需走 PassKey
    return "MFA_REQUIRED"


@pytest.mark.parametrize(
    "is_otp,has_passkey,code_state",
    list(itertools.product([True, False], [True, False], ["none", "valid", "invalid"])),
)
def test_mfa_matches_frozen_truth_table(monkeypatch, is_otp, has_passkey, code_state):
    import app.db.models.passkey as passkey_mod
    import app.utils.otp as otp_mod

    otp_valid = code_state == "valid"
    code = None if code_state == "none" else "123456"
    expected = _expected_legacy(is_otp, has_passkey, code_state)

    # (a) evaluate_mfa + 内建因子（注入 fake 判定，db-free）
    factors = build_builtin_factors(
        is_otp_enrolled=lambda ref: is_otp,
        verify_otp=lambda ref, c: otp_valid,
        has_passkey=lambda ref: has_passkey,
    )
    new = evaluate_mfa(MfaUserRef(user_id=1, username="admin"), MfaSubmission(code=code), factors)
    assert _KIND_TO_LEGACY[new.kind] == expected, (
        f"evaluate_mfa mismatch @ is_otp={is_otp} passkey={has_passkey} code={code_state}: "
        f"expected={expected!r} got_kind={new.kind!r}")

    # (b) PR3 委托式 _verify_mfa（monkeypatch PassKey/OtpUtils 注入同样判定）
    monkeypatch.setattr(passkey_mod.PassKey, "get_by_user_id",
                        staticmethod(lambda db=None, user_id=None: ([object()] if has_passkey else [])))
    monkeypatch.setattr(otp_mod.OtpUtils, "check",
                        staticmethod(lambda secret, password: otp_valid))
    fake_user = types.SimpleNamespace(id=1, name="admin", is_otp=is_otp, otp_secret="SECRET")
    assert UserChain._verify_mfa(fake_user, code) == expected, (
        f"_verify_mfa mismatch @ is_otp={is_otp} passkey={has_passkey} code={code_state}")
