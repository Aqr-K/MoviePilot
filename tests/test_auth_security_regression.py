# -*- coding: utf-8 -*-
"""安全回归套件 — 锁定插件化认证框架的安全不变量。

每条测试对应一个明确的安全威胁或不变量；凡已有散件覆盖者均以明确安全名 CONSOLIDATE，
保证任意单一测试可独立描述所捍卫的威胁。

硬门① (test_hard_metric_1_no_mechanism_imports):
    flow_engine / core/auth/flow 无具体机制导入 — 插件化核心与机制解耦。

硬门② (test_hard_metric_2_new_mechanism_is_one_step):
    证明"新机制 = 1 IAuthStep"经真实生产装配路径 _build_flow_service()（读 all_auth_steps()）
    驱动完整登录，resolve_or_create 被调用，最终 status==success。
"""

import inspect
import re
import types
from types import SimpleNamespace

import pytest

from app.core.auth.flow import (
    AllOf,
    AnyOf,
    AuthContext,
    AuthStepResult,
    IdentityAssertion,
    NOf,
    StepRef,
)
from app.service.auth.flow_engine import AuthFlow, FlowStore
from app.service.auth.flow_service import FlowService, redact_reason
from app.service.auth.flow_steps import FactorStep, PasswordStep


# ============================================================
# 共用工具
# ============================================================

def _sub(**kw):
    return SimpleNamespace(**kw)


def _ctx(flow_id="sec-test"):
    return AuthContext(flow_id=flow_id, username="alice")


# ============================================================
# 1. 动态强 MFA — 不足因子绝不死锁
# ============================================================

def test_dynamic_strong_mfa_insufficient_factors_fails_not_hangs():
    """NOf(2, ...) 策略 + 仅 1 个注册因子 → _validate_requirement 降级为 AnyOf；
    流程终止为 success，绝不永久循环 mfa_required。

    威胁: 若 NOf(n) 降级失败，用户即使提交了所有因子也无法完成 MFA。
    """
    from app.service.auth.builtin_factors import OtpFactor

    USERS = {2: SimpleNamespace(id=2, name="mfauser", is_active=True)}

    def _factor_steps_for(user):
        if user.id == 2:
            return [FactorStep(OtpFactor(
                is_enrolled=lambda ref: True,
                verify=lambda ref, code: code == "246",
            ))]
        return []

    nof2_strategy = lambda steps: NOf(2, [StepRef(s.step_id) for s in steps])

    svc = FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[PasswordStep(
            authenticate=lambda u, p: USERS[2] if u == "mfauser" and p == "pw" else None
        )],
        factor_steps_for=_factor_steps_for,
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
        mfa_requirement=nof2_strategy,
    )

    out = svc.begin(_sub(username="mfauser", password="pw"))
    assert out["status"] == "mfa_required", f"expected mfa_required after credential, got {out}"

    # NOf(2) with only 1 enrolled factor must be downgraded; correct code → success, not loop.
    out2 = svc.advance(out["flow_token"], _sub(step_id="otp", code="246"))
    assert out2["status"] == "success", (
        f"flow must terminate (downgrade to AnyOf → success), never hang; got {out2}"
    )


# ============================================================
# 2. 静态流程规格 — 不可满足步骤返回 failure 不死锁
# ============================================================

def test_static_flowspec_unsatisfiable_step_fails():
    """AllOf 内含 applies_to 恒 False 的步骤 → 引擎检测死局，返回 failure（不循环）。

    威胁: 若引擎不检测死局，认证永远处于 mfa_required/pending，形成 DoS 隐患。
    """
    class _NeverApplies:
        step_id = "ghost"
        step_kind = "factor"
        priority = 1
        def applies_to(self, c): return False
        def advance(self, c, s): return AuthStepResult(status="pending")

    class _CredStep:
        step_id = "password"
        step_kind = "credential"
        priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=1)

    flow = AuthFlow(
        {"password": _CredStep(), "ghost": _NeverApplies()},
        AllOf([StepRef("password"), StepRef("ghost")]),
        trusted_step_ids=frozenset({"password"}),
    )
    ctx = _ctx("unsatisfiable-1")
    ctx, r1 = flow.advance(ctx, _sub(username="u", password="p"))
    # Credential done; ghost is permanently non-actionable → deadlock → failure.
    ctx, r2 = flow.advance(ctx, None)
    assert r2.kind == "failure", f"unsatisfiable step must cause failure, got kind={r2.kind}"


# ============================================================
# 3. 运行时注册漂移 — 已满足步骤后剩余不可达 → failure
# ============================================================

def test_runtime_enrollment_drift_terminates():
    """凭证满足后 MFA 因子的 applies_to 动态变 False（注册被撤销）→ 终止为 failure，不循环。

    威胁: 凭证阶段通过后，若 MFA 因子被撤销且引擎不检测，流程永久卡住。
    """
    enrolled = [True]  # mutable sentinel simulating enrollment revocation

    class _DriftFactor:
        step_id = "drift-otp"
        step_kind = "factor"
        priority = 5

        def applies_to(self, ctx):
            return ctx.resolved_user_id is not None and enrolled[0]

        def advance(self, ctx, s):
            return AuthStepResult(status="pending")  # always needs more input

    class _PwdStep:
        step_id = "password"
        step_kind = "credential"
        priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=5)

    flow = AuthFlow(
        {"password": _PwdStep(), "drift-otp": _DriftFactor()},
        AllOf([StepRef("password"), StepRef("drift-otp")]),
        trusted_step_ids=frozenset({"password"}),
    )
    ctx = _ctx("drift-1")
    ctx, r1 = flow.advance(ctx, _sub(username="u", password="p"))
    assert r1.kind == "mfa_required", f"expected mfa_required initially, got {r1.kind}"

    # Simulate enrollment revoked before next advance
    enrolled[0] = False

    ctx, r2 = flow.advance(ctx, None)
    assert r2.kind == "failure", f"after drift, must terminate as failure, got {r2.kind}"


# ============================================================
# 4. 插件步骤 user_id 冒充被护栏丢弃
# ============================================================

def test_plugin_step_userid_imposter_dropped():
    """非受信步骤给出 user_id=1（含 identity_resolver 配置）→ 护栏拒绝；
    resolved_user_id 保持 None，流程 failure，resolver 未被调用。

    威胁: 若护栏不阻断，恶意插件可声称任意 user_id（包括管理员 id=1）绕过认证。
    """
    class _Imposter:
        step_id = "evil-cred"
        step_kind = "credential"
        priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=1)

    resolver_called = []
    flow = AuthFlow(
        {"evil-cred": _Imposter()},
        StepRef("evil-cred"),
        identity_resolver=lambda assertion: (resolver_called.append(assertion) or None),
        trusted_step_ids=frozenset(),  # evil-cred is NOT in trusted set
    )
    ctx, result = flow.advance(_ctx("imposter-1"), _sub())
    assert result.kind == "failure", (
        f"non-trusted step carrying user_id must be rejected, got kind={result.kind}"
    )
    assert ctx.resolved_user_id is None, "resolved_user_id must stay None after guardian rejection"
    assert not resolver_called, "identity_resolver must NOT be called for user_id impersonation"


# ============================================================
# 4b. 装配桥 — 冒充内建 id 的插件步被排除
# ============================================================

def test_builtin_id_spoof_excluded_from_assembly():
    """插件注册 step_id=='password' 的步骤时，_build_flow_service 的 _BUILTIN_CREDENTIAL_IDS
    过滤器将其排除；credential_steps 中唯一的 'password' 是内建 PasswordStep。
    (frozenset 防冒充)

    威胁: 若无过滤，插件可以 step_id='password' 影子化内建步骤，使其 user_id 直接落地。
    """
    from app.api.endpoints.auth import _build_flow_service, _BUILTIN_CREDENTIAL_IDS
    from app.core.auth.steps import register_auth_step, unregister_auth_steps

    assert "password" in _BUILTIN_CREDENTIAL_IDS, "sanity: 'password' must be a builtin credential id"

    class _SpoofPwd:
        step_id = "password"
        step_kind = "credential"
        priority = 99  # would outrank builtin if filter failed
        _is_spoof = True

        def applies_to(self, c): return True
        def advance(self, c, s): return AuthStepResult(status="failed", error="spoof")

    register_auth_step(_SpoofPwd(), owner="spoof-plugin")
    try:
        svc = _build_flow_service()
        pwd_steps = [s for s in svc._credential_steps if getattr(s, "step_id", None) == "password"]
        assert len(pwd_steps) == 1, (
            f"exactly one 'password' step must exist in credential_steps, found {len(pwd_steps)}"
        )
        assert isinstance(pwd_steps[0], PasswordStep), (
            f"the sole 'password' step must be the builtin PasswordStep, got {type(pwd_steps[0])}"
        )
        assert not getattr(pwd_steps[0], "_is_spoof", False), (
            "spoof plugin step must not have replaced the builtin 'password' step"
        )
    finally:
        unregister_auth_steps("spoof-plugin")


# ============================================================
# 5. 插件默认流程 empty-true 无法绕过 MFA
# ============================================================

def test_plugin_default_flow_empty_true_cannot_bypass_mfa():
    """AllOf([]) 和 NOf(0, ...) 对空 satisfied 集即满足（空真），
    verify_flow_spec_contract 必须拒绝注册。

    威胁: 插件以 flow_id='default' 注册空真规格，所有用户无需完成任何因子即视为 MFA 通过。
    """
    from app.core.auth.flow_registry import verify_flow_spec_contract

    class _EmptyAllOf:
        flow_id = "default"
        def mfa_requirement(self, steps): return AllOf([])

    class _ZeroNOf:
        flow_id = "default"
        def mfa_requirement(self, steps):
            return NOf(0, [StepRef(s.step_id) for s in steps])

    ok_a, reasons_a = verify_flow_spec_contract(_EmptyAllOf())
    assert not ok_a, f"AllOf([]) empty-true must be rejected; reasons={reasons_a}"
    assert any("空真" in r or "vacuous" in r.lower() for r in reasons_a), (
        f"rejection reason must mention empty-true bypass; got {reasons_a}"
    )

    ok_n, reasons_n = verify_flow_spec_contract(_ZeroNOf())
    assert not ok_n, f"NOf(0) empty-true must be rejected; reasons={reasons_n}"


# ============================================================
# 6. 跨 provider state 绑定被拒绝
# ============================================================

def test_state_cross_provider_rejected():
    """RedirectStep 回调的 state.provider_id != step.provider_id → failed / invalid_state。
    防止攻击者把为 'other-provider' 签发的 CSRF state 复用到 'github' step。
    (spec §4.7 cross-provider binding)

    威胁: 若不校验 provider_id 绑定，攻击者可用任意 provider 的 state 完成任意 provider 的回调。
    """
    from app.service.auth.flow_steps import RedirectStep

    class _GithubProvider:
        provider_id = "github"
        priority = 100
        def fetch_identity(self, code, redirect_uri): ...  # never reached

    # Simulate attacker supplying a state issued for "other-provider"
    cross_state = "state-for-other-provider"

    step = RedirectStep(
        provider=_GithubProvider(),
        consume_state=lambda s: (
            {"flow_token": "ft-x", "provider_id": "other-provider"}
            if s == cross_state else None
        ),
    )
    ctx = _ctx("cross-provider-1")
    submission = _sub(code="legit-code", state=cross_state, step_id="github")
    result = step.advance(ctx, submission)
    assert result.status == "failed", (
        f"cross-provider state must be rejected with failed, got status={result.status!r}"
    )
    assert result.error == "invalid_state", (
        f"error must be 'invalid_state', got {result.error!r}"
    )


# ============================================================
# 7. 并发 advance 丢失更新受 CAS 保护
# ============================================================

def test_concurrent_advance_lost_update_guarded():
    """并发的两个 advance 调用竞争同一 flow_token；后到者（stale version）收到 operation_conflict，
    胜出方写入的状态不被覆盖。

    威胁: 若无 CAS，两个并发请求可能撕裂流程状态，导致认证状态不一致。
    """
    class _PendingCred:
        step_id = "pending-cred"
        step_kind = "credential"
        priority = 1
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="pending")

    USERS = {1: SimpleNamespace(id=1, name="u", is_active=True)}
    store = FlowStore(ttl_seconds=600)
    svc = FlowService(
        flow_store=store,
        credential_steps=[_PendingCred()],
        factor_steps_for=lambda user: [],
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
    )

    out = svc.begin(_sub(username="test"))
    assert out["status"] == "continue"
    flow_token = out["flow_token"]

    # Winner bumps version from v1 → v2 out-of-band
    ctx_snap, v1 = store.load_versioned(flow_token)
    ok, v2 = store.save(ctx_snap, expected_version=v1)
    assert ok and v2 == v1 + 1

    # Late racer's advance sees stale v1 via monkeypatched load_versioned
    original_lv = store.load_versioned
    stale_used = []

    def _stale_load(fid):
        if fid == flow_token and not stale_used:
            stale_used.append(True)
            return (ctx_snap, v1)
        return original_lv(fid)

    store.load_versioned = _stale_load
    out2 = svc.advance(flow_token, _sub())
    assert out2["status"] == "failure", f"late racer must fail, got {out2['status']}"
    assert out2.get("error") == "operation_conflict", (
        f"error must be 'operation_conflict', got {out2.get('error')!r}"
    )

    # Winner's state at v2 must be intact
    store.load_versioned = original_lv
    surviving, cv = store.load_versioned(flow_token)
    assert surviving is not None, "winner's flow state must not be dropped by the losing advance"
    assert cv == v2, f"winning version v2={v2} must be preserved, found cv={cv}"


# ============================================================
# 8. 原因脱敏 — 未知错误映射为 auth_failed
# ============================================================

def test_reason_redaction_maps_unknown_error():
    """自由文本 / 含 IP / 内部细节 → 脱敏为 auth_failed；白名单安全代码直通。

    威胁: 若内部错误原文泄漏到 HTTP 响应，攻击者可枚举用户名、发现 LDAP 拓扑等。
    """
    # Free-text / internal details → redacted
    assert redact_reason("LDAP bind 10.0.0.1 refused") == "auth_failed"
    assert redact_reason("provider 校验异常") == "auth_failed"
    assert redact_reason("random internal detail xyz") == "auth_failed"
    # Whitelisted safe codes pass through
    assert redact_reason("invalid_state") == "invalid_state"
    assert redact_reason("invalid_code") == "invalid_code"
    assert redact_reason("fetch_identity_failed") == "fetch_identity_failed"
    assert redact_reason("用户名或密码错误") == "用户名或密码错误"


# ============================================================
# 9. 限流 — 超阈值返回 429
# ============================================================

@pytest.fixture()
def _reset_login_limiter():
    """Ensure login rate limiter starts clean for this test."""
    from app.api.endpoints import login as m
    lim = getattr(m, "_auth_rate_limiter", None)
    if lim:
        lim.clear()
    yield
    if lim:
        lim.clear()


def test_rate_limit_returns_429(monkeypatch, _reset_login_limiter):
    """同一 (ip+username) 在短窗口内超过阈值 → HTTP 429（含友好提示）。

    威胁: 无限流则凭证暴力穷举在技术上可行。
    """
    from fastapi import HTTPException
    from starlette.requests import Request
    from starlette.responses import Response

    from app.api.endpoints import login as login_mod
    from app.utils.limit import KeyedWindowRateLimiter

    tight = KeyedWindowRateLimiter(max_calls=2, window_seconds=60)
    monkeypatch.setattr(login_mod, "_auth_rate_limiter", tight)

    class _FailSvc:
        def run_sync(self, sub):
            return {"status": "failure", "error": "invalid_credentials"}

    monkeypatch.setattr(login_mod, "_build_flow_service", lambda: _FailSvc())
    monkeypatch.setattr(login_mod, "emit_auth_event", lambda *a, **kw: None)

    req = Request({
        "type": "http", "method": "POST",
        "path": "/api/v1/login/access-token",
        "headers": [(b"host", b"testserver")],
        "scheme": "http", "server": ("testserver", 80),
        "client": ("testclient", 123),
    })
    form = SimpleNamespace(username="brute", password="bad")
    resp = Response()

    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            login_mod.login_access_token(request=req, response=resp, form_data=form)
        assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        login_mod.login_access_token(request=req, response=resp, form_data=form)
    assert exc.value.status_code == 429
    assert "频繁" in exc.value.detail


# ============================================================
# 10. 观测事件 schema 一致性
# ============================================================

def test_observability_events_schema_parity(monkeypatch):
    """emit_auth_event 对 success / failure / mfa_required 均发送 schema 一致的事件，
    且 failure 原因已脱敏（无内部细节）。

    威胁: 若 failure 事件携带原始错误，审计日志消费者可能二次泄漏内部信息。
    """
    from app.api.endpoints.auth import emit_auth_event
    from app.schemas.event import AuthObservationEventData, MfaChallengeEventData

    emitted = []

    def _capture(etype, data):
        emitted.append((etype, data))

    monkeypatch.setattr("app.api.endpoints.auth.eventmanager.send_event", _capture)

    # ---- success event ----
    emit_auth_event(
        {"status": "success", "token": SimpleNamespace(user_name="alice")},
        "alice", "127.0.0.1",
    )
    assert len(emitted) == 1
    _, ev_ok = emitted[0]
    assert isinstance(ev_ok, AuthObservationEventData)
    assert ev_ok.username == "alice"
    assert ev_ok.success is True
    assert ev_ok.client_ip == "127.0.0.1"
    emitted.clear()

    # ---- failure event — raw error must be redacted ----
    emit_auth_event(
        {"status": "failure", "error": "LDAP bind 10.0.0.1 refused"},
        "bob", "10.0.0.2",
    )
    assert len(emitted) == 1
    _, ev_fail = emitted[0]
    assert isinstance(ev_fail, AuthObservationEventData)
    assert ev_fail.username == "bob"
    assert ev_fail.success is False
    reason = ev_fail.reason or ""
    assert reason == "auth_failed", (
        f"raw internal error must be redacted to 'auth_failed', got {reason!r}"
    )
    assert "LDAP" not in reason and "10.0.0.1" not in reason
    emitted.clear()

    # ---- mfa_required event ----
    emit_auth_event(
        {"status": "mfa_required", "factors_available": ["otp", "sms"]},
        "carol", "10.0.0.3",
    )
    assert len(emitted) == 1
    _, ev_mfa = emitted[0]
    assert isinstance(ev_mfa, MfaChallengeEventData)
    assert ev_mfa.username == "carol"
    assert set(ev_mfa.factors_available) == {"otp", "sms"}


# ============================================================
# 硬门① — 核心引擎无具体机制导入
# ============================================================

def test_hard_metric_1_no_mechanism_imports():
    """flow_engine.py 与 core/auth/flow.py 不直接 import 任何具体机制。
    保证插件化核心与认证机制彻底解耦 — 新机制只需贡献一个 IAuthStep。

    威胁: 若核心有具体机制依赖，每增加机制都需修改核心文件（开放-封闭原则违反）。
    """
    import app.core.auth.flow as _core_flow
    import app.service.auth.flow_engine as _flow_engine

    # Pattern: any `import` line (import / from … import) mentioning a concrete mechanism
    pattern = re.compile(r'import\b.*?\b(ldap|otp|passkey|sms|sso|webauthn)\b', re.IGNORECASE)
    for mod in (_flow_engine, _core_flow):
        src = inspect.getsource(mod)
        matches = pattern.findall(src)
        assert not matches, (
            f"{mod.__file__} contains concrete-mechanism import(s): {matches!r}"
        )


# ============================================================
# 硬门② — 新机制 = 1 步骤，经真实生产装配 e2e
# ============================================================

def test_hard_metric_2_new_mechanism_is_one_step(monkeypatch):
    """证明"新机制 = 1 IAuthStep (no new Challenge variant)"经真实生产装配路径驱动完整登录。

    装配路径 (硬门②):
        register_auth_step(DemoDirectoryStep, owner="demoplugin")
        → all_auth_steps()           [步骤注册表]
        → _build_flow_service()      [生产装配桥]
        → FlowService.run_sync()     [多步登录服务]
        → identity_resolver(IdentityAssertion)  [owner-routing 端口]
        → resolve_or_create (monkeypatched)     [身份落地，验证被调用]
        → load_user(42)              [加载本地用户]
        → issue_token(user)          [铸 Token]
        → status == 'success'        [端到端成功]

    硬门② 关键不变量:
    - DemoDirectoryStep 无 user_id — 必须经 identity_resolver 端口落地（非受信 owner-routing）。
    - resolve_or_create 被实际调用（通过 assertion 参数验证）。
    - 整条路径未跳过任何生产代码（仅 stub DB / token 铸造）。
    """
    from app.api.endpoints import auth as _auth_mod
    from app.api.endpoints.auth import _build_flow_service
    from app.core.auth.steps import register_auth_step, unregister_auth_steps

    # ── stub user (no DB rows needed) ──────────────────────────────────────
    _STUB_USER = SimpleNamespace(
        id=42, is_active=True, name="demo-user", is_otp=False, otp_secret="",
    )

    # ── define the single new-mechanism step (directory kind) ──────────────
    class DemoDirectoryStep:
        """One new mechanism = exactly one IAuthStep; no new Challenge variant needed."""
        step_id = "demo-dir-step"
        step_kind = "directory"   # directory is in _CREDENTIAL_STEP_KINDS
        priority = 50

        def applies_to(self, ctx):
            return ctx.resolved_user_id is None

        def advance(self, ctx, submission):
            # Returns IdentityAssertion (NO user_id) — must go through resolver port.
            return AuthStepResult(
                status="satisfied",
                identity=IdentityAssertion(
                    provider_id="demo",
                    subject="demo-user",
                    username="demo-user",
                    auto_create=False,
                ),
            )

    # ── monkeypatching ─────────────────────────────────────────────────────
    # 1. resolve_or_create in flow_steps.py module namespace
    #    (make_identity_resolver uses the module-level symbol; test seam documented there)
    resolver_calls = []

    def _fake_resolve(provider_id, *, subject, username=None, avatar=None, auto_create, deps):
        resolver_calls.append({"provider_id": provider_id, "subject": subject})
        return _STUB_USER

    monkeypatch.setattr("app.service.auth.flow_steps.resolve_or_create", _fake_resolve)

    # 2. User name in auth module → fake class with .get() returning stub user
    #    (load_user lambda in _build_flow_service closes over module-level 'User')
    FakeUser = type("FakeUser", (), {
        "get": staticmethod(lambda db=None, rid=None, **kw: _STUB_USER),
    })
    monkeypatch.setattr(_auth_mod, "User", FakeUser)

    # 3. build_token_response in auth module namespace
    monkeypatch.setattr(
        _auth_mod, "build_token_response",
        lambda user: {"access_token": f"demo-tok-{user.id}", "user_name": user.name},
    )

    # 4. _builtin_factor_steps: no builtin factors for stub user (no OTP/passkey in DB)
    monkeypatch.setattr(_auth_mod, "_builtin_factor_steps", lambda user: [])

    # ── register the demo step ─────────────────────────────────────────────
    register_auth_step(DemoDirectoryStep(), owner="demoplugin")
    try:
        # ── assemble via REAL production bridge ────────────────────────────
        svc = _build_flow_service()

        # Invariant: DemoDirectoryStep appears in credential_steps after registry read
        cred_ids = [getattr(s, "step_id", None) for s in svc._credential_steps]
        assert "demo-dir-step" in cred_ids, (
            f"demo-dir-step must be assembled into credential_steps via all_auth_steps(); "
            f"found: {cred_ids}"
        )
        # Invariant: "password" (builtin) also present
        assert "password" in cred_ids, (
            f"builtin 'password' step must always be present; found: {cred_ids}"
        )

        # ── drive a login (no password → PasswordStep pending, DemoStep satisfied) ──
        #    run_sync feeds the same submission to begin() + advance() until terminal state
        out = svc.run_sync(_sub(username="demo-user"))

        # ── verify the identity resolver was actually invoked ───────────────
        assert resolver_calls, (
            "resolve_or_create must be called for a non-trusted step's IdentityAssertion"
        )
        assert resolver_calls[0]["provider_id"] == "demo", (
            f"resolver must be called with provider_id='demo', got {resolver_calls[0]}"
        )
        assert resolver_calls[0]["subject"] == "demo-user", (
            f"resolver must be called with subject='demo-user', got {resolver_calls[0]}"
        )

        # ── verify end-to-end success ───────────────────────────────────────
        assert out["status"] == "success", (
            f"full e2e via real _build_flow_service must reach success; got status={out.get('status')!r}, "
            f"full={out}"
        )
        assert out["token"]["access_token"] == "demo-tok-42", (
            f"token must come from patched issue_token; got {out.get('token')}"
        )

    finally:
        unregister_auth_steps("demoplugin")
