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


# ----------------------------- 联合方断言 MFA 已满足 → 跳过 MFA -----------------------------
class _FederatedCredStep:
    """联合凭证步骤：认证成功并断言外部已完成 MFA（mfa_satisfied=True）。"""
    step_id = "fed"
    step_kind = "credential"
    priority = 5

    def applies_to(self, ctx):
        return ctx.resolved_user_id is None

    def advance(self, ctx, submission):
        from app.core.auth.flow import AuthStepResult
        return AuthStepResult(status="satisfied", user_id=2, mfa_satisfied=True)


def test_federated_mfa_satisfied_skips_mfa_stage():
    # otpuser(id=2) 启用了 OTP；但联合方断言 MFA 已满足 → 应直接成功，不进 MFA 阶段
    svc = FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[_FederatedCredStep()],
        factor_steps_for=_factor_steps_for,   # 对 id=2 会返回 OTP 因子
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
    )
    out = svc.begin(_sub(username="otpuser", password="anything"))
    assert out["status"] == "success"          # mfa_satisfied 短路，未要求 OTP
    assert out["token"]["access_token"] == "TK-2"


# ----------------------------- FlowStore CAS -----------------------------
def test_flowstore_cas():
    from app.core.auth.flow import AuthContext
    from app.service.auth.flow_engine import FlowStore
    s = FlowStore()
    c = AuthContext(flow_id="f1")
    assert s.save(c)[0]
    _, v = s.load_versioned("f1")
    s.save(c, expected_version=v)
    assert s.save(c, expected_version=v)[0] is False


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


# ============================= S1 tests (Task 10) =============================

# ----------------------------- _run_mfa enrolled 子集防死锁 -----------------------------
def test_run_mfa_enrolled_no_deadlock():
    """单注册因子用户在 N-of-2 策略下不应死锁：_validate_requirement 降级为 AnyOf，正确码即成功。"""
    from app.core.auth.flow import NOf, StepRef
    # 策略要求 2-of-enrolled，但 otpuser(id=2) 仅有 1 个 OTP 因子
    nof2_strategy = lambda steps: NOf(2, [StepRef(s.step_id) for s in steps])
    svc = FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[_password_step()],
        factor_steps_for=_factor_steps_for,
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
        mfa_requirement=nof2_strategy,
    )
    out = svc.begin(_sub(username="otpuser", password="pw"))
    assert out["status"] == "mfa_required", f"expected mfa_required, got {out}"
    # 提交正确 OTP：降级后 AnyOf([otp]) 即满足，不应永久 mfa_required
    out2 = svc.advance(out["flow_token"], _sub(step_id="otp", code="246"))
    assert out2["status"] == "success", f"expected success after downgrade, got {out2}"


# ----------------------------- run_sync 密码直通 -----------------------------
def test_sync_password_only():
    """run_sync：nomfa 用户一轮密码即成功，返回 status==success + token。"""
    svc, _ = _service()
    out = svc.run_sync(_sub(username="nomfa", password="pw"))
    assert out["status"] == "success"
    assert out["token"]["access_token"] == "TK-1"


# ----------------------------- _after_credential challenge 分支 -----------------------------
class _SsoCredStep:
    """伪 SSO 凭证步：always 返回 RedirectChallenge（授权 URL 下发挑战）。"""
    step_id = "github"
    step_kind = "credential"
    priority = 10

    def applies_to(self, ctx):
        return ctx.resolved_user_id is None

    def advance(self, ctx, submission):
        from app.core.auth.challenge import RedirectChallenge
        from app.core.auth.flow import AuthStepResult
        return AuthStepResult(
            status="challenge",
            challenge=RedirectChallenge(
                step_id="github", provider_id="github",
                authorize_url="https://github.com/login/oauth/authorize?client_id=x"))


def test_after_credential_challenge():
    """begin 触发 SSO 重定向挑战时，status 应为 challenge 并携带 authorize_url，而非被错归为 continue。"""
    svc = FlowService(
        flow_store=FlowStore(ttl_seconds=600),
        credential_steps=[_SsoCredStep()],
        factor_steps_for=lambda user: [],
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
    )
    out = svc.begin(_sub())
    assert out["status"] == "challenge", f"expected challenge, got {out}"
    assert out["challenge"]["kind"] == "redirect"
    assert "authorize_url" in out["challenge"]
    assert out.get("flow_token")


# ----------------------------- redact_reason 脱敏 -----------------------------
def test_redact_reason():
    """未知自由文本错误原因应脱敏为 auth_failed；白名单内的安全代码直通。"""
    from app.service.auth.flow_service import redact_reason
    # 自由文本（含 IP / 内部信息）→ 脱敏
    assert redact_reason("LDAP bind 10.0.0.1 refused") == "auth_failed"
    assert redact_reason("provider 校验异常") == "auth_failed"
    assert redact_reason("random internal detail xyz") == "auth_failed"
    # 白名单安全代码直通
    assert redact_reason("invalid_state") == "invalid_state"
    assert redact_reason("invalid_code") == "invalid_code"
    assert redact_reason("fetch_identity_failed") == "fetch_identity_failed"
    assert redact_reason("用户名或密码错误") == "用户名或密码错误"


# ----------------------------- _validate_requirement 非空真拒绝 -----------------------------
def test_validate_requirement_rejects_empty_true():
    """AllOf([]) 对空集即为真（空真）→ _validate_requirement 降级为 AnyOf，防绕过 MFA。"""
    from app.core.auth.flow import AllOf
    svc, _ = _service()
    otp_step = FactorStep(OtpFactor(
        is_enrolled=lambda ref: True,
        verify=lambda ref, code: code == "246"))
    # AllOf([]) 对任意 satisfied 集合均满足（包括空集）
    empty_true = AllOf([])
    assert empty_true.is_satisfied(frozenset()), "前置：AllOf([]) 对空集确实为真"
    result = svc._validate_requirement(empty_true, [otp_step])
    # 降级后不应对空集满足
    assert not result.is_satisfied(frozenset()), "降级后不应对空 satisfied 集满足"


# ============================= S1 tests (Task 12.5) =============================

# ----------------------------- CAS lost-update 防护 -----------------------------
def test_flowservice_advance_cas_conflict():
    """Racing advance (credential stage) with stale version → operation_conflict, winning state intact.

    Simulate two concurrent advance() calls on a multi-step credential flow:
    1. begin() saves initial state unconditionally at version v1.
    2. A concurrent "winner" bumps the store to v2 out-of-band.
    3. The "late racer" advance() is monkey-patched to see stale v1 from load_versioned.
    4. advance() processes the step (still pending → tries to save), but CAS fails (v1 ≠ v2).
    5. Returns operation_conflict WITHOUT dropping the winning state.
    """
    from app.core.auth.flow import AuthStepResult

    class _PendingCredStep:
        """Credential step that always returns pending — needs more input (multi-round cred flow)."""
        step_id = "pending_cred"
        step_kind = "credential"
        priority = 1

        def applies_to(self, ctx):
            return ctx.resolved_user_id is None

        def advance(self, ctx, submission):
            return AuthStepResult(status="pending")

    store = FlowStore(ttl_seconds=600)
    svc = FlowService(
        flow_store=store,
        credential_steps=[_PendingCredStep()],
        factor_steps_for=lambda user: [],
        load_user=lambda uid: USERS.get(uid),
        issue_token=lambda user: {"access_token": f"TK-{user.id}"},
    )

    # begin() saves state unconditionally → version 1, returns "continue"
    out = svc.begin(_sub(username="test"))
    assert out["status"] == "continue"
    flow_token = out["flow_token"]

    ctx, v1 = store.load_versioned(flow_token)
    assert v1 >= 1

    # Simulate concurrent winner bumping the version (v1 → v2)
    ok, v2 = store.save(ctx, expected_version=v1)
    assert ok and v2 == v1 + 1

    # Monkey-patch load_versioned so the late racer's advance() loads stale v1.
    # When _after_credential tries save(expected_version=v1) against actual v2 → CAS fails.
    original_lv = store.load_versioned
    stale_used = []

    def _stale_load_versioned(fid):
        if fid == flow_token and not stale_used:
            stale_used.append(True)
            return (ctx, v1)
        return original_lv(fid)

    store.load_versioned = _stale_load_versioned

    out2 = svc.advance(flow_token, _sub())
    assert out2["status"] == "failure"
    assert out2.get("error") == "operation_conflict"

    # Winning writer's state (v2) must NOT have been dropped by the losing advance
    store.load_versioned = original_lv
    surviving, cv = store.load_versioned(flow_token)
    assert surviving is not None, "winning writer's flow state must not be dropped by the loser"
    assert cv == v2
