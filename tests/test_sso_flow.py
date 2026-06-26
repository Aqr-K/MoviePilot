# -*- coding: utf-8 -*-
"""阶段3：SSO 经 ``FlowService`` 统一驱动 —— callback 走流程引擎、自动接条件 MFA、成功铸 ticket 交浏览器。

证明 SSO 与密码/凭据 provider 走同一条流程引擎：无因子直接成功，有因子则要求第二因子
（复用通用 ``advance``），并验证 callback 结果 → 前端跳转 query 的纯分流。
"""
import types

from app.service.auth.builtin_factors import OtpFactor
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_steps import FactorStep
from app.service.auth.sso_flow import build_sso_flow_service, sso_callback_query


def _sub(**kw):
    return types.SimpleNamespace(**kw)


class _FakeIdp:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"
    priority = 100
    auto_create = True

    def fetch_identity(self, code, redirect_uri):
        return types.SimpleNamespace(subject="42", username="octo", avatar=None)


def _ok_deps(user):
    from app.service.auth.provisioning import ProvisioningDeps
    state = {"created": False}
    return ProvisioningDeps(
        get_binding=lambda p, s: None,
        get_user_by_id=lambda uid: user,
        get_user_by_name=lambda n: user if state["created"] else None,
        create_user=lambda name, avatar=None: state.__setitem__("created", True),
        list_bindings_for_user=lambda uid: [],
        create_binding=lambda **kw: None,
    )


def _otp_factor():
    return FactorStep(OtpFactor(is_enrolled=lambda ref: True, verify=lambda ref, code: code == "246"))


def _state_ok(s):
    # 迁移（Task 9）：consume_state 现返载荷 dict（含 provider_id，须匹配 provider），而非旧 bool
    return {"provider_id": "github"}


# ----------------------------- SSO 经 flow：无 MFA → 直接铸 ticket -----------------------------
def test_sso_flow_no_mfa_issues_ticket():
    user = types.SimpleNamespace(id=7, name="octo", is_active=True)
    svc = build_sso_flow_service(
        _FakeIdp(), flow_store=FlowStore(), factors_for_user=lambda u: [],
        load_user=lambda uid: user, issue_ticket=lambda u: f"TICKET-{u.id}",
        deps=_ok_deps(user), consume_state=_state_ok)
    out = svc.begin(_sub(step_id="github", code="abc123", state="st", redirect_uri="cb"))
    assert out["status"] == "success"
    assert out["token"] == "TICKET-7"


# ----------------------------- SSO 经 flow：有 MFA → 要求第二因子，补码后成功 -----------------------------
def test_sso_flow_with_mfa_requires_factor_then_succeeds():
    user = types.SimpleNamespace(id=7, name="octo", is_active=True)
    svc = build_sso_flow_service(
        _FakeIdp(), flow_store=FlowStore(), factors_for_user=lambda u: [_otp_factor()],
        load_user=lambda uid: user, issue_ticket=lambda u: f"TICKET-{u.id}",
        deps=_ok_deps(user), consume_state=_state_ok)
    out = svc.begin(_sub(step_id="github", code="abc123", state="st", redirect_uri="cb"))
    assert out["status"] == "mfa_required"               # SSO 用户有因子 → 不再豁免 MFA
    out2 = svc.advance(out["flow_token"], _sub(step_id="otp", code="246"))
    assert out2["status"] == "success"
    assert out2["token"] == "TICKET-7"


# ----------------------------- callback 结果 → 前端跳转 query（HTTP 无关纯分流）-----------------------------
def test_sso_callback_query_success_carries_ticket():
    assert sso_callback_query({"status": "success", "token": "TK"}) == {"ticket": "TK"}


def test_sso_callback_query_mfa_carries_flow_token():
    q = sso_callback_query({"status": "mfa_required", "flow_token": "FT", "factors_available": ["otp"]})
    assert q == {"flow_token": "FT", "sso_mfa": "1"}


def test_sso_callback_query_failure_carries_error():
    assert sso_callback_query({"status": "failure", "error": "invalid_state"}) == {"sso_error": "invalid_state"}
