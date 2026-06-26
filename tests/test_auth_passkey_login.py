# -*- coding: utf-8 -*-
"""通行密钥（WebAuthn）登录入统一流程引擎的单元测试。

经依赖注入（begin_fn / verify_fn / store）避免真实 WebAuthn 加密，覆盖：
  - begin {flow:"system:passkey"} → 下发 WebAuthnChallenge；
  - advance 带断言 → success 且落 user_id；
  - usernameless（无用户名仍能发挑战）；
  - 重放（同一流程令牌第二次 consume 为空 → invalid_state）；
  - 受信（PasskeyLoginStep 直落 user_id，配 resolver 的引擎仍接受；非受信则护栏丢弃）。
"""
import types

from app.core.auth.challenge import WebAuthnChallenge
from app.core.auth.flow import AnyOf, AuthContext, StepRef
from app.service.auth.flow_engine import AuthFlow, FlowStore
from app.service.auth.flow_service import FlowService
from app.service.auth.flow_steps import PasskeyLoginStep, PasswordStep
from app.service.auth.passkey_login import PasskeyChallengeStore, PasskeyLoginError


def _sub(**kw):
    return types.SimpleNamespace(**kw)


def _store():
    return PasskeyChallengeStore(ttl_seconds=600)


def _begin_ok(username=None):
    return ('{"options": 1}', "chal-abc")


def _verify_user(uid=42):
    return lambda response, expected: types.SimpleNamespace(id=uid)


# ----------------------------- (a) begin → WebAuthnChallenge -----------------------------
def test_passkey_step_issues_webauthn_challenge():
    store = _store()
    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=_verify_user(), store=store)
    r = step.advance(AuthContext(flow_id="f1", requested_step_id="system:passkey"),
                     _sub(response=None))
    assert r.status == "challenge"
    assert isinstance(r.challenge, WebAuthnChallenge)
    assert r.challenge.kind == "webauthn"
    assert r.challenge.step_id == "system:passkey"
    assert r.challenge.to_dict()["options"] == '{"options": 1}'
    # 挑战已落服务端（键=flow_id），未泄漏给挑战载荷
    assert store.consume("f1") == "chal-abc"


def _flow_service(store, begin_fn, verify_fn, trusted=frozenset({"password", "system:passkey"})):
    return FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[PasswordStep(authenticate=lambda u, p: None),
                          PasskeyLoginStep(begin_fn=begin_fn, verify_fn=verify_fn, store=store)],
        factor_steps_for=lambda user: [],
        load_user=lambda uid: types.SimpleNamespace(id=uid, name="pk", is_active=True),
        issue_token=lambda user: {"access_token": f"TK-{user.id}", "user_name": user.name},
        identity_resolver=lambda a: None,
        trusted_step_ids=trusted,
    )


def test_begin_flow_passkey_emits_challenge_then_advance_succeeds():
    # (a) begin {flow:"system:passkey"} 下发挑战；(b) advance 带断言 → success 落 user_id
    store = _store()
    svc = _flow_service(store, _begin_ok, _verify_user(uid=42))
    out = svc.begin(_sub(username=None, flow="system:passkey"))
    assert out["status"] == "challenge"
    assert out["challenge"]["kind"] == "webauthn"
    assert out["challenge"]["options"] == '{"options": 1}'

    out2 = svc.advance(out["flow_token"], _sub(step_id="system:passkey", response={"id": "x"}))
    assert out2["status"] == "success"
    assert out2["token"]["access_token"] == "TK-42"


# ----------------------------- (c) usernameless -----------------------------
def test_usernameless_begin_issues_challenge():
    captured = {}

    def begin(username=None):
        captured["username"] = username
        return ("{}", "chal-usernameless")

    store = _store()
    step = PasskeyLoginStep(begin_fn=begin, verify_fn=_verify_user(), store=store)
    r = step.advance(AuthContext(flow_id="f2", requested_step_id="system:passkey"),
                     _sub(response=None))
    assert r.status == "challenge"
    assert captured["username"] is None  # 无用户名 → usernameless（discoverable credential）
    assert store.consume("f2") == "chal-usernameless"


# ----------------------------- (d) 重放：第二次 consume 为空 -----------------------------
def test_replay_second_consume_fails_invalid_state():
    store = _store()
    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=_verify_user(uid=7), store=store)
    ctx = AuthContext(flow_id="f3", requested_step_id="system:passkey")
    step.advance(ctx, _sub(response=None))                       # 下发并登记挑战
    r1 = step.advance(ctx, _sub(response={"id": "x"}))           # 首次断言 → 取即销毁
    assert r1.status == "satisfied" and r1.user_id == 7
    r2 = step.advance(ctx, _sub(response={"id": "x"}))           # 重放同一流程令牌
    assert r2.status == "failed"
    assert r2.error == "invalid_state"


def test_missing_challenge_is_invalid_state():
    # 无 begin（未登记挑战）直接带断言 → invalid_state（防绕过发起态）
    store = _store()
    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=_verify_user(), store=store)
    r = step.advance(AuthContext(flow_id="f-x", requested_step_id="system:passkey"),
                     _sub(response={"id": "x"}))
    assert r.status == "failed" and r.error == "invalid_state"


def test_verify_failure_returns_invalid_passkey():
    store = _store()

    def verify(response, expected):
        raise PasskeyLoginError("nope")

    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=verify, store=store)
    ctx = AuthContext(flow_id="f6", requested_step_id="system:passkey")
    step.advance(ctx, _sub(response=None))
    r = step.advance(ctx, _sub(response={"id": "x"}))
    assert r.status == "failed" and r.error == "invalid_passkey"


# ----------------------------- opt-in 前置门控 -----------------------------
def test_passkey_step_is_opt_in():
    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=_verify_user(), store=_store())
    assert step.applies_to(AuthContext(flow_id="f", requested_step_id="system:passkey")) is True
    assert step.applies_to(AuthContext(flow_id="f")) is False                       # 未选中
    assert step.applies_to(
        AuthContext(flow_id="f", requested_step_id="system:passkey").with_resolved_user(1)
    ) is False                                                                       # 已解析用户


# ----------------------------- (e) 受信直落 user_id -----------------------------
def _drive_step_in_flow(trusted):
    store = _store()
    step = PasskeyLoginStep(begin_fn=_begin_ok, verify_fn=_verify_user(uid=9), store=store)
    flow = AuthFlow({"system:passkey": step}, AnyOf([StepRef("system:passkey")]),
                    identity_resolver=lambda a: None, trusted_step_ids=trusted)
    base = AuthContext(flow_id="f-trust", requested_step_id="system:passkey")
    flow.advance(base, _sub(step_id="system:passkey", response=None))               # 登记挑战
    return flow.advance(base, _sub(step_id="system:passkey", response={"id": "x"}))


def test_passkey_user_id_accepted_when_trusted():
    # 配了 resolver 的引擎里，受信内建步仍可直落 user_id（不经 identity 端口）
    ctx, result = _drive_step_in_flow(frozenset({"system:passkey"}))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 9


def test_passkey_user_id_dropped_when_untrusted():
    # owner-routing 护栏：非受信步直接给 user_id 被引擎丢弃（对照受信用例）
    ctx, result = _drive_step_in_flow(frozenset())
    assert result.kind == "failure"
    assert ctx.resolved_user_id is None


# ----------------------------- 装配桥：system:passkey 进受信集 + 提供方摘要 -----------------------------
def test_build_flow_service_includes_trusted_passkey_step():
    from app.api.endpoints.auth import _build_flow_service, _BUILTIN_CREDENTIAL_IDS

    assert "system:passkey" in _BUILTIN_CREDENTIAL_IDS
    svc = _build_flow_service()
    cred_ids = [getattr(s, "step_id", None) for s in svc._credential_steps]
    assert "system:passkey" in cred_ids
    assert "system:passkey" in svc._trusted_step_ids


def test_system_passkey_provider_summary(monkeypatch):
    from app.api.endpoints import auth as auth_module

    monkeypatch.setattr(auth_module.PassKey, "list",
                        classmethod(lambda cls, db=None: []))
    providers = auth_module._system_auth_providers()
    pk = next(p for p in providers if p["id"] == "system:passkey")
    assert pk["flow"] == "system:passkey"
    assert pk["login_url"] == auth_module._FLOW_BEGIN_PATH
