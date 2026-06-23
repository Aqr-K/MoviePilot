# -*- coding: utf-8 -*-
"""MfaFactorRegistry 单元测试（PR1，纯增量基础设施）。"""
import pytest

from app.core.auth.mfa_factors import (
    MfaFactorRegistry,
    MfaSubmission,
    MfaUserRef,
    verify_mfa_factor_contract,
)
from app.core.auth.outcome import MfaFactorResult


class _Factor:
    """满足 IMfaFactor 契约的测试桩。"""

    def __init__(self, fid="otp", kind="possession", priority=10, name="OTP"):
        self.factor_id = fid
        self.factor_kind = kind
        self.display_name = name
        self.priority = priority

    def is_enrolled(self, user_ref):
        return True

    def verify(self, user_ref, submission):
        return MfaFactorResult(status="allow")

    def challenge_hint(self, user_ref):
        return None


def test_contract_accepts_valid():
    ok, reasons = verify_mfa_factor_contract(_Factor())
    assert ok and reasons == []


@pytest.mark.parametrize("bad", [
    _Factor(fid="bad_id"),    # 含下划线
    _Factor(kind="nope"),     # 非法 factor_kind
    _Factor(name=123),        # display_name 非字符串
    _Factor(priority="x"),    # priority 非整数
])
def test_contract_rejects_invalid(bad):
    ok, reasons = verify_mfa_factor_contract(bad)
    assert not ok and reasons


def test_register_get_collision_unregister():
    reg = MfaFactorRegistry()
    assert reg.register(_Factor(fid="otp"), owner="a")[0]
    assert reg.get("otp") is not None
    ok, msg = reg.register(_Factor(fid="otp"), owner="b")   # 跨 owner 撞 id
    assert not ok and "冲突" in msg
    reg.register(_Factor(fid="sms"), owner="b")
    reg.unregister("b")
    assert reg.get("sms") is None
    assert reg.get("otp") is not None


def test_all_sorted_by_priority():
    reg = MfaFactorRegistry()
    reg.register(_Factor(fid="passkey", priority=20), owner="o")
    reg.register(_Factor(fid="otp", priority=10), owner="o")
    assert [f.factor_id for f in reg.all()] == ["otp", "passkey"]


def test_submission_and_userref_defaults():
    s = MfaSubmission(code="123456")
    assert s.factor_id is None and s.response == {}
    ref = MfaUserRef(user_id=1, username="admin")
    assert ref.username == "admin" and ref.user_id == 1
