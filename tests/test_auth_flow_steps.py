# -*- coding: utf-8 -*-
"""PR10：把现有 ``IMfaFactor`` / ``ICredentialProvider`` / 本地密码包装为流程 ``IAuthStep`` 的适配器。

证明引擎可零改动地驱动**现有**因子与 provider 对象（构件级复用，逻辑不重复实现），
并支持任意组合（N-of-M）与挑战-应答。
"""
import types

from app.core.auth.flow import AllOf, AnyOf, AuthContext, IdentityAssertion, NOf, StepRef
from app.core.auth.outcome import CredentialOutcome
from app.service.auth.builtin_factors import OtpFactor, PasskeyFactor
from app.service.auth.flow_engine import AuthFlow
from app.service.auth.flow_steps import (
    CredentialProviderStep,
    FactorStep,
    PasswordStep,
    RedirectStep,
    build_credential_flow,
    build_mfa_flow,
    make_identity_resolver,
)
from app.service.auth.provisioning import ProvisioningDeps


def _state_ok(provider_id="github"):
    """新版 consume_state 契约（Task 6）：返回载荷 dict（含 provider_id），而非旧的 bool。"""
    return lambda s: {"provider_id": provider_id}


def _sub(**kw):
    return types.SimpleNamespace(**kw)


def _resolved_ctx(user_id=1, username="alice"):
    return AuthContext(flow_id="f1", username=username).with_resolved_user(user_id)


# ----------------------------- FactorStep over 内建 OtpFactor -----------------------------
def _otp_step(enrolled=True, good_code="123456", step_id=None):
    otp = OtpFactor(is_enrolled=lambda ref: enrolled,
                    verify=lambda ref, code: code == good_code)
    return FactorStep(otp, step_id=step_id)


def test_otp_factor_step_issues_prompt():
    # S1: 无码提交且因子已注册 → 下发 PromptChallenge（kind="prompt", input_kind="otp"）
    step = _otp_step()  # enrolled=True, no step_id override → step_id == "otp"
    r = step.advance(_resolved_ctx(), _sub())  # no code, no response
    assert r.status == "challenge"
    assert r.challenge.kind == "prompt"
    assert r.challenge.input_kind == "otp"
    assert r.challenge.step_id == step.step_id


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
    # 迁移（Task 9）：凭证步现交回 identity，由引擎注入的 resolver 落地 user_id（resolver 注入式迁移）
    user = types.SimpleNamespace(id=500, is_active=True)
    step = CredentialProviderStep(_FakeLdap({"alice": "secret"}))
    flow = AuthFlow({"ldap": step}, AnyOf([StepRef("ldap")]),
                    identity_resolver=lambda a: 500)
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
    ldap = CredentialProviderStep(_FakeLdap({"alice": "dir"}))
    # 迁移（Task 9）：注入 resolver 把目录 provider 交回的 identity 落地为 user2（resolver 注入式迁移）
    flow = build_credential_flow([pw, ldap], identity_resolver=lambda a: 2)
    ctx, result = flow.advance(AuthContext(flow_id="f1", username="alice"),
                               _sub(grant_type="password", username="alice", password="dir"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 2  # 本地密码不符 → 回落目录 provider


# ----------------------------- SSO 统一为 step -----------------------------
class _FakeRedirectProvider:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"
    priority = 100


def test_redirect_step_emits_authorize_url_challenge():
    step = RedirectStep(_FakeRedirectProvider(),
                        authorize_url_builder=lambda p: "https://idp.example.com/auth?state=xyz")
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]))
    _, result = flow.advance(AuthContext(flow_id="f1"), _sub(step_id="github"))
    assert result.kind == "challenge"
    assert result.challenge["kind"] == "redirect"
    assert result.challenge["provider_id"] == "github"
    assert result.challenge["authorize_url"].startswith("https://idp.example.com/auth")


def test_redirect_step_in_or_with_password():
    # 组合：密码 OR GitHub-SSO —— 选 SSO 即下发跳转挑战（不影响密码路径）
    user = types.SimpleNamespace(id=1, is_active=True)
    pw = PasswordStep(authenticate=lambda u, p: user if p == "pw" else None)
    redirect = RedirectStep(_FakeRedirectProvider(), authorize_url_builder=lambda p: "https://idp/x")
    flow = build_credential_flow([pw, redirect])
    _, picked_sso = flow.advance(AuthContext(flow_id="f1", username="alice"),
                                 _sub(step_id="github"))
    assert picked_sso.kind == "challenge"
    ctx, picked_pw = flow.advance(AuthContext(flow_id="f1", username="alice"),
                                  _sub(step_id="password", username="alice", password="pw"))
    assert picked_pw.kind == "success" and ctx.resolved_user_id == 1


# ----------------------------- RedirectStep 双模（带授权码完成回调认证）-----------------------------
class _FakeRedirectIdp:
    """带 ``fetch_identity`` 的重定向 provider：用于驱动 RedirectStep 的"回调应答"分支。"""

    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"
    priority = 100
    auto_create = True

    def __init__(self, identity=None, raise_fetch=False):
        self._identity = identity
        self._raise = raise_fetch

    def fetch_identity(self, code, redirect_uri):
        if self._raise:
            raise RuntimeError("boom")
        return self._identity


def _redirect_identity(subject="42", username="octo", avatar=None):
    return types.SimpleNamespace(subject=subject, username=username, avatar=avatar)


def _reject_deps():
    # 未绑定 + auto_create，但同名残留账号已禁用 → resolve_or_create 触发 B-4 拒绝（返回 None）
    return ProvisioningDeps(
        get_binding=lambda p, s: None,
        get_user_by_id=lambda uid: None,
        get_user_by_name=lambda n: types.SimpleNamespace(id=3, is_active=False),
        create_user=lambda name, avatar=None: None,
        list_bindings_for_user=lambda uid: [],
        create_binding=lambda **kw: None,
    )


def test_redirect_step_with_code_resolves_user_and_satisfies():
    # 回调应答（带授权码）：CSRF 通过 → fetch_identity → 交回 identity → 引擎 resolver 落地 user_id
    # 迁移（Task 9）：consume_state 改返载荷 dict；resolver 注入式落地 user 7
    step = RedirectStep(_FakeRedirectIdp(identity=_redirect_identity(subject="42", username="octo")),
                        consume_state=_state_ok())
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]),
                    identity_resolver=lambda a: 7)
    ctx, result = flow.advance(AuthContext(flow_id="f1"),
                               _sub(step_id="github", code="abc123", state="st", redirect_uri="cb"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 7


def test_redirect_step_invalid_state_fails():
    # CSRF state 校验失败 → 整步失败（绝不继续换身份）
    step = RedirectStep(_FakeRedirectIdp(identity=_redirect_identity()),
                        deps=_ok_deps(types.SimpleNamespace(id=7, is_active=True)),
                        consume_state=lambda s: False)
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]))
    _, result = flow.advance(AuthContext(flow_id="f1"),
                             _sub(step_id="github", code="abc", state="bad", redirect_uri="cb"))
    assert result.kind == "failure"


def test_redirect_step_fetch_identity_none_fails():
    # 迁移（Task 9）：consume_state 返载荷 dict，使本例真正走到 fetch_identity=None 分支
    step = RedirectStep(_FakeRedirectIdp(identity=None), consume_state=_state_ok())
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]), identity_resolver=lambda a: 7)
    _, result = flow.advance(AuthContext(flow_id="f1"),
                             _sub(step_id="github", code="abc", state="st", redirect_uri="cb"))
    assert result.kind == "failure"


def test_redirect_step_provisioning_rejected_fails():
    # 迁移（Task 9）：护栏单一来源仍是 resolve_or_create，但现经引擎注入的 resolver 落地——
    # identity → make_identity_resolver(_reject_deps) → B-4 拒绝返回 None → 引擎拒绝落地 → 整步失败。
    # 关键安全不变量：未通过护栏的外部身份**绝不**能落得 user_id。
    step = RedirectStep(_FakeRedirectIdp(identity=_redirect_identity(subject="42")),
                        consume_state=_state_ok())
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]),
                    identity_resolver=make_identity_resolver(_reject_deps()))
    ctx, result = flow.advance(AuthContext(flow_id="f1"),
                               _sub(step_id="github", code="abc", state="st", redirect_uri="cb"))
    assert result.kind == "failure"
    assert ctx.resolved_user_id is None


def test_redirect_step_invalid_code_fails():
    # 非法授权码（含换行等注入字符）在换身份前被拒（边界校验，迁移自旧 complete_login）
    # 迁移（Task 9）：consume_state 返载荷 dict，使本例真正走到 is_valid_code 边界校验分支
    step = RedirectStep(_FakeRedirectIdp(identity=_redirect_identity()), consume_state=_state_ok())
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]), identity_resolver=lambda a: 7)
    _, result = flow.advance(AuthContext(flow_id="f1"),
                             _sub(step_id="github", code="bad\ncode", state="st", redirect_uri="cb"))
    assert result.kind == "failure"


def test_redirect_step_fetch_identity_raises_is_safe():
    # provider.fetch_identity 抛异常 → 安全失败（不泄露、不 500；迁移自旧 complete_login）
    step = RedirectStep(_FakeRedirectIdp(raise_fetch=True),
                        deps=_ok_deps(types.SimpleNamespace(id=7, is_active=True)),
                        consume_state=_state_ok())
    flow = AuthFlow({"github": step}, AnyOf([StepRef("github")]))
    _, result = flow.advance(AuthContext(flow_id="f1"),
                             _sub(step_id="github", code="abc", state="st", redirect_uri="cb"))
    assert result.kind == "failure"


# ----------------------------- Task 9: 直验/SSO Step 交回 IdentityAssertion + resolver -----------------------------
def test_cred_step_identity():
    # 直验 Step 成功 → 交回 IdentityAssertion（user_id=None，**不**在步内自调 resolve_or_create）
    step = CredentialProviderStep(_FakeLdap({"alice": "secret"}))
    r = step.advance(AuthContext(flow_id="f1", username="alice"),
                     _sub(grant_type="password", username="alice", password="secret"))
    assert r.status == "satisfied" and r.user_id is None
    assert r.identity is not None
    assert r.identity.subject == "alice" and r.identity.provider_id == "ldap"


def test_redirect_challenge():
    # 无授权码 → 直接返回 RedirectChallenge（kind="redirect"，带 authorize_url）
    step = RedirectStep(_FakeRedirectProvider(),
                        authorize_url_builder=lambda p: "https://idp/a")
    r = step.advance(AuthContext(flow_id="f1"), _sub(code=None))
    assert r.status == "challenge"
    assert r.challenge.kind == "redirect"
    assert r.challenge.authorize_url == "https://idp/a"


def test_make_identity_resolver(monkeypatch):
    # 经 module-level resolve_or_create（测试缝）把 IdentityAssertion 解析为本地 user_id
    import app.service.auth.flow_steps as fs
    monkeypatch.setattr(fs, "resolve_or_create", lambda pid, **kw: types.SimpleNamespace(id=7))
    resolver = make_identity_resolver(deps=object())
    assert resolver(IdentityAssertion(provider_id="ldap", subject="s")) == 7


def test_make_identity_resolver_none_when_guard_rejects(monkeypatch):
    # resolve_or_create 触发护栏返回 None → resolver 返回 None（引擎据此拒绝落地）
    import app.service.auth.flow_steps as fs
    monkeypatch.setattr(fs, "resolve_or_create", lambda pid, **kw: None)
    resolver = make_identity_resolver(deps=object())
    assert resolver(IdentityAssertion(provider_id="ldap", subject="s")) is None
