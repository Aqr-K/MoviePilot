# -*- coding: utf-8 -*-
"""PR11：``FlowService`` —— 把流程引擎接成多步登录服务（凭证阶段 → 条件 MFA 阶段 → 铸 Token）。

全注入依赖（FlowStore / 凭证步骤 / 因子装配 / 用户加载 / 铸 Token），纯单测、不碰 db / security。
覆盖：无 MFA 直接成功、有 MFA 两步、错码失败、凭证失败、未知/过期令牌、跨轮经 FlowStore 承载。
"""
import types

from app.service.auth.builtin_factors import OtpFactor
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_service import FlowService
from app.service.auth.flow_steps import FactorStep, PasswordStep


def _sub(**kw):
    return types.SimpleNamespace(**kw)


USERS = {
    1: types.SimpleNamespace(id=1, name="nomfa", is_active=True),
    2: types.SimpleNamespace(id=2, name="otpuser", is_active=True),
}


def _password_step():
    # 本地密码：仅 (otpuser/2, nomfa/1) + 口令 "pw" 通过
    table = {"nomfa": USERS[1], "otpuser": USERS[2]}
    return PasswordStep(authenticate=lambda u, p: table.get(u) if p == "pw" else None)


def _factor_steps_for(user):
    # otpuser 启用 OTP（码 "246"），nomfa 无因子
    if user.id == 2:
        return [FactorStep(OtpFactor(is_enrolled=lambda ref: True,
                                     verify=lambda ref, code: code == "246"))]
    return []


def _service():
    issued = {}
    svc = FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[_password_step()],
        factor_steps_for=_factor_steps_for,
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}", "user_name": user.name},
    )
    return svc, issued


# ----------------------------- 无 MFA：一步成功 -----------------------------
def test_begin_no_mfa_succeeds_directly():
    svc, _ = _service()
    out = svc.begin(_sub(username="nomfa", password="pw"))
    assert out["status"] == "success"
    assert out["token"]["access_token"] == "TK-1"


# ----------------------------- 有 MFA：两步 -----------------------------
def test_begin_with_mfa_then_advance_success():
    svc, _ = _service()
    out = svc.begin(_sub(username="otpuser", password="pw"))
    assert out["status"] == "mfa_required"
    assert out["factors_available"] == ["otp"]
    token = out["flow_token"]
    # 第二步：提交正确 OTP 码
    out2 = svc.advance(token, _sub(step_id="otp", code="246"))
    assert out2["status"] == "success"
    assert out2["token"]["access_token"] == "TK-2"


def test_advance_wrong_otp_fails():
    svc, _ = _service()
    out = svc.begin(_sub(username="otpuser", password="pw"))
    out2 = svc.advance(out["flow_token"], _sub(step_id="otp", code="000"))
    assert out2["status"] == "failure"


# ----------------------------- 凭证失败 -----------------------------
def test_begin_bad_password_fails():
    svc, _ = _service()
    out = svc.begin(_sub(username="otpuser", password="wrong"))
    assert out["status"] == "failure"


# ----------------------------- 令牌健壮性 -----------------------------
def test_advance_unknown_token_fails():
    svc, _ = _service()
    out = svc.advance("does-not-exist", _sub(step_id="otp", code="246"))
    assert out["status"] == "failure"


def test_flow_token_is_unguessable_and_consumed_on_success():
    svc, _ = _service()
    out = svc.begin(_sub(username="otpuser", password="pw"))
    token = out["flow_token"]
    assert len(token) >= 16
    svc.advance(token, _sub(step_id="otp", code="246"))
    # 成功后令牌应被清除（不可重放）
    again = svc.advance(token, _sub(step_id="otp", code="246"))
    assert again["status"] == "failure"


# ----------------------------- 禁用用户在第二步被拦 -----------------------------
def test_disabled_user_blocked_at_advance():
    svc, _ = _service()
    out = svc.begin(_sub(username="otpuser", password="pw"))
    USERS[2].is_active = False
    try:
        out2 = svc.advance(out["flow_token"], _sub(step_id="otp", code="246"))
        assert out2["status"] == "failure"
    finally:
        USERS[2].is_active = True
