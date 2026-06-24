# -*- coding: utf-8 -*-
"""PR10：把现有 ``IMfaFactor`` / ``ICredentialProvider`` / 本地密码包装为流程 ``IAuthStep`` 的适配器。

证明引擎可零改动地驱动**现有**因子与 provider 对象（构件级复用，逻辑不重复实现），
并支持任意组合（N-of-M）与挑战-应答。
"""
import types

from app.core.auth.flow import AllOf, AnyOf, AuthContext, NOf, StepRef
from app.core.auth.outcome import CredentialOutcome
from app.service.auth.builtin_factors import OtpFactor, PasskeyFactor
from app.service.auth.flow_engine import AuthFlow
from app.service.auth.flow_steps import (
    CredentialProviderStep,
    FactorStep,
    PasswordStep,
    build_credential_flow,
    build_mfa_flow,
)
from app.service.auth.provisioning import ProvisioningDeps


def _sub(**kw):
    return types.SimpleNamespace(**kw)


def _resolved_ctx(user_id=1, username="alice"):
    return AuthContext(flow_id="f1", username=username).with_resolved_user(user_id)


# ----------------------------- FactorStep over 内建 OtpFactor -----------------------------
def _otp_step(enrolled=True, good_code="123456", step_id=None):
    otp = OtpFactor(is_enrolled=lambda ref: enrolled,
                    verify=lambda ref, code: code == good_code)
    return FactorStep(otp, step_id=step_id)


def test_factor_step_not_actionable_before_user_resolved():
    step = _otp_step()
    assert step.applies_to(AuthContext(flow_id="f1")) is False          # 未解析用户 → 不可推进


def test_factor_step_not_actionable_when_not_enrolled():
    step = _otp_step(enrolled=False)
    assert step.applies_to(_resolved_ctx()) is False


def test_factor_step_correct_code_satisfies():
    flow = AuthFlow({"otp": _otp_step()}, AnyOf([StepRef("otp")]))
    _, result = flow.advance(_resolved_ctx(), _sub(step_id="otp", code="123456"))
    assert result.kind == "success"


def test_factor_step_wrong_code_fails():
    flow = AuthFlow({"otp": _otp_step()}, AnyOf([StepRef("otp")]))
    _, result = flow.advance(_resolved_ctx(), _sub(step_id="otp", code="000000"))
    assert result.kind == "failure"


def test_passkey_step_emits_challenge():
    # PasskeyFactor.verify 恒为 challenge_required → 适配为 challenge
    flow = AuthFlow({"passkey": FactorStep(PasskeyFactor(is_enrolled=lambda ref: True))},
                    AnyOf([StepRef("passkey")]))
    _, result = flow.advance(_resolved_ctx(), _sub(step_id="passkey", code="x"))
    assert result.kind in ("challenge", "mfa_required")  # 需走独立 passkey 端点


# ----------------------------- CredentialProviderStep over 假 provider -----------------------------
class _FakeLdap:
    provider_id = "ldap"
    factor_kind = "directory"
    priority = 50
    auto_create = True

    def __init__(self, directory):
        self._dir = directory

    def applies_to(self, req):
        return req.grant_type == "password" and bool(req.username) and bool(req.password)

    def verify_credentials(self, req):
        if req.username not in self._dir:
            return CredentialOutcome(status="not_mine")
        if self._dir[req.username] != req.password:
            return CredentialOutcome(status="reject")
        return CredentialOutcome(status="success", username=req.username, extra={"subject": req.username})


def _ok_deps(user_obj):
    state = {"created": False}
    return ProvisioningDeps(
        get_binding=lambda p, s: None,
        get_user_by_id=lambda uid: user_obj,
        get_user_by_name=lambda n: user_obj if state["created"] else None,
        create_user=lambda name, avatar=None: state.__setitem__("created", True),
        list_bindings_for_user=lambda uid: [],
        create_binding=lambda **kw: None,
    )


def test_credential_provider_step_success_resolves_user():
    user = types.SimpleNamespace(id=500, is_active=True)
    step = CredentialProviderStep(_FakeLdap({"alice": "secret"}), deps=_ok_deps(user))
    flow = AuthFlow({"ldap": step}, AnyOf([StepRef("ldap")]))
    ctx, result = flow.advance(AuthContext(flow_id="f1", username="alice"),
                               _sub(grant_type="password", username="alice", password="secret"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 500


def test_credential_provider_step_reject_fails():
    user = types.SimpleNamespace(id=500, is_active=True)
    step = CredentialProviderStep(_FakeLdap({"alice": "secret"}), deps=_ok_deps(user))
    flow = AuthFlow({"ldap": step}, AnyOf([StepRef("ldap")]))
    _, result = flow.advance(AuthContext(flow_id="f1", username="alice"),
                             _sub(grant_type="password", username="alice", password="wrong"))
    assert result.kind == "failure"


# ----------------------------- PasswordStep（注入校验）-----------------------------
def test_password_step_with_injected_authenticate():
    user = types.SimpleNamespace(id=1, is_active=True)
    step = PasswordStep(authenticate=lambda u, p: user if (u == "alice" and p == "pw") else None)
    flow = AuthFlow({"password": step}, AnyOf([StepRef("password")]))
    ctx, ok = flow.advance(AuthContext(flow_id="f1"), _sub(username="alice", password="pw"))
    assert ok.kind == "success" and ctx.resolved_user_id == 1
    _, bad = flow.advance(AuthContext(flow_id="f1"), _sub(username="alice", password="nope"))
    assert bad.kind == "failure"


# ----------------------------- 构建器 + N-of-M 组合 -----------------------------
def test_build_mfa_flow_n_of_m_over_real_factors():
    # 3 选 2 的强 MFA：三个内建 OtpFactor + 各自覆写 step_id，证明组合策略经构建器生效
    f1 = _otp_step(good_code="111", step_id="a")
    f2 = _otp_step(good_code="222", step_id="b")
    f3 = _otp_step(good_code="333", step_id="c")
    flow = build_mfa_flow([f1, f2, f3], NOf(2, [StepRef("a"), StepRef("b"), StepRef("c")]))
    ctx, r1 = flow.advance(_resolved_ctx(), _sub(step_id="a", code="111"))
    assert r1.kind == "mfa_required"
    ctx, r2 = flow.advance(ctx, _sub(step_id="b", code="222"))
    assert r2.kind == "success"


def test_build_credential_flow_or_fallback():
    user1 = types.SimpleNamespace(id=1, is_active=True)
    user2 = types.SimpleNamespace(id=2, is_active=True)
    pw = PasswordStep(authenticate=lambda u, p: user1 if p == "local" else None)
    ldap = CredentialProviderStep(_FakeLdap({"alice": "dir"}), deps=_ok_deps(user2))
    flow = build_credential_flow([pw, ldap])
    ctx, result = flow.advance(AuthContext(flow_id="f1", username="alice"),
                               _sub(grant_type="password", username="alice", password="dir"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 2  # 本地密码不符 → 回落目录 provider
