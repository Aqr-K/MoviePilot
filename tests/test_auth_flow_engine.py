# -*- coding: utf-8 -*-
"""PR9：流程引擎 ``AuthFlow.advance`` + ``FlowStore`` —— 用假 step 证明任意组合/排序/多轮推进。

覆盖：单凭证成功/失败、凭证→MFA 两轮、错误 MFA 码失败、N-of-M 三轮、挑战-应答往返、
凭证 OR 回落到下一个 provider，以及 FlowStore 跨轮承载不可变状态。
"""
import types

from app.core.auth.flow import AllOf, AnyOf, AuthContext, AuthStepResult, NOf, StepRef
from app.service.auth.flow_engine import AuthFlow, FlowStore


# ----------------------------- 假 step -----------------------------
class FakeCredential:
    step_kind = "credential"

    def __init__(self, step_id="pw", priority=0, user_id=1, password="secret", mfa_satisfied=False):
        self.step_id = step_id
        self.priority = priority
        self._user_id = user_id
        self._password = password
        self._mfa_satisfied = mfa_satisfied

    def applies_to(self, ctx):
        return ctx.resolved_user_id is None

    def advance(self, ctx, submission):
        pw = getattr(submission, "password", None)
        if pw is None:
            return AuthStepResult(status="pending")
        if pw == self._password:
            return AuthStepResult(status="satisfied", user_id=self._user_id,
                                  mfa_satisfied=self._mfa_satisfied)
        return AuthStepResult(status="failed", error="bad password")


class FakeFactor:
    step_kind = "factor"

    def __init__(self, step_id, priority=10, code="000"):
        self.step_id = step_id
        self.priority = priority
        self._code = code

    def applies_to(self, ctx):
        return ctx.resolved_user_id is not None

    def advance(self, ctx, submission):
        target = getattr(submission, "step_id", None)
        if target not in (None, self.step_id):
            return AuthStepResult(status="pending")
        code = getattr(submission, "code", None)
        if code is None:
            return AuthStepResult(status="pending")
        if code == self._code:
            return AuthStepResult(status="satisfied")
        return AuthStepResult(status="failed", error="bad code")


class FakeChallengeFactor:
    """SMS 类：无码时下发挑战，带正确码时通过。"""
    step_id = "sms"
    step_kind = "factor"
    priority = 20

    def applies_to(self, ctx):
        return ctx.resolved_user_id is not None

    def advance(self, ctx, submission):
        if getattr(submission, "step_id", None) not in (None, "sms"):
            return AuthStepResult(status="pending")
        code = getattr(submission, "code", None)
        if code is None:
            return AuthStepResult(status="challenge", challenge={"delivery": "sms", "sent": True})
        if code == "246810":
            return AuthStepResult(status="satisfied")
        return AuthStepResult(status="failed", error="bad code")


def _sub(**kw):
    return types.SimpleNamespace(**kw)


def _flow(steps, requirement):
    return AuthFlow(steps={s.step_id: s for s in steps}, requirement=requirement)


def _ctx():
    return AuthContext(flow_id="f1", username="alice")


# ----------------------------- 单凭证 -----------------------------
def test_single_credential_success():
    flow = _flow([FakeCredential(user_id=42)], AllOf([StepRef("pw")]))
    ctx, result = flow.advance(_ctx(), _sub(password="secret"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 42


def test_single_credential_failure():
    flow = _flow([FakeCredential()], AllOf([StepRef("pw")]))
    ctx, result = flow.advance(_ctx(), _sub(password="wrong"))
    assert result.kind == "failure"
    assert ctx.resolved_user_id is None


# ----------------------------- 凭证 → MFA 两轮 -----------------------------
def test_credential_then_mfa_two_rounds():
    flow = _flow([FakeCredential(user_id=7), FakeFactor("otp", code="123"), FakeFactor("passkey", code="zzz")],
                 AllOf([StepRef("pw"), AnyOf([StepRef("otp"), StepRef("passkey")])]))
    # R1：仅凭证 → 需要第二因子
    ctx, r1 = flow.advance(_ctx(), _sub(password="secret"))
    assert r1.kind == "mfa_required"
    assert set(r1.factors_available) == {"otp", "passkey"}
    assert ctx.resolved_user_id == 7
    # R2：提交 otp 码 → 成功
    ctx, r2 = flow.advance(ctx, _sub(step_id="otp", code="123"))
    assert r2.kind == "success"


def test_wrong_mfa_code_fails():
    flow = _flow([FakeCredential(user_id=7), FakeFactor("otp", code="123")],
                 AllOf([StepRef("pw"), StepRef("otp")]))
    ctx, _ = flow.advance(_ctx(), _sub(password="secret"))
    ctx, r2 = flow.advance(ctx, _sub(step_id="otp", code="999"))
    assert r2.kind == "failure"


# ----------------------------- N-of-M（3 选 2）三轮 -----------------------------
def test_n_of_m_two_of_three():
    flow = _flow(
        [FakeCredential(user_id=5),
         FakeFactor("otp", code="111"), FakeFactor("sms", code="222"), FakeFactor("pk", code="333")],
        AllOf([StepRef("pw"), NOf(2, [StepRef("otp"), StepRef("sms"), StepRef("pk")])]),
    )
    ctx, r1 = flow.advance(_ctx(), _sub(password="secret"))
    assert r1.kind == "mfa_required" and set(r1.factors_available) == {"otp", "sms", "pk"}
    ctx, r2 = flow.advance(ctx, _sub(step_id="otp", code="111"))
    assert r2.kind == "mfa_required" and set(r2.factors_available) == {"sms", "pk"}  # 还差 1
    ctx, r3 = flow.advance(ctx, _sub(step_id="sms", code="222"))
    assert r3.kind == "success"


# ----------------------------- 挑战-应答往返 -----------------------------
def test_challenge_response_roundtrip():
    flow = _flow([FakeCredential(user_id=9), FakeChallengeFactor()],
                 AllOf([StepRef("pw"), StepRef("sms")]))
    ctx, _ = flow.advance(_ctx(), _sub(password="secret"))
    # 选 sms 但未带码 → 下发挑战
    ctx, rc = flow.advance(ctx, _sub(step_id="sms"))
    assert rc.kind == "challenge"
    assert rc.challenge == {"delivery": "sms", "sent": True}
    assert ctx.challenges["sms"]["sent"] is True
    # 带正确码 → 成功
    ctx, rs = flow.advance(ctx, _sub(step_id="sms", code="246810"))
    assert rs.kind == "success"


# ----------------------------- 凭证 OR 回落 -----------------------------
def test_credential_or_falls_back_to_next_provider():
    # 本地密码先试（priority 0）但口令不符 → 回落到目录 provider（priority 50）
    local = FakeCredential(step_id="pw", priority=0, user_id=1, password="local-secret")
    ldap = FakeCredential(step_id="ldap", priority=50, user_id=99, password="dir-secret")
    flow = _flow([local, ldap], AllOf([AnyOf([StepRef("pw"), StepRef("ldap")])]))
    ctx, result = flow.advance(_ctx(), _sub(password="dir-secret"))
    assert result.kind == "success"
    assert ctx.resolved_user_id == 99  # 目录 provider 接管


# ----------------------------- FlowStore -----------------------------
def test_flowstore_save_load_drop():
    store = FlowStore(ttl_seconds=600)
    ctx = AuthContext(flow_id="tok-1", username="bob").with_satisfied("pw").with_resolved_user(3)
    ok, _ver = store.save(ctx)
    assert ok is True
    loaded = store.load("tok-1")
    assert loaded.username == "bob"
    assert loaded.satisfied_steps == frozenset({"pw"})
    assert loaded.resolved_user_id == 3
    store.drop("tok-1")
    assert store.load("tok-1") is None


def test_flowstore_carries_progress_across_rounds():
    store = FlowStore(ttl_seconds=600)
    flow = _flow([FakeCredential(user_id=7), FakeFactor("otp", code="123")],
                 AllOf([StepRef("pw"), StepRef("otp")]))
    ctx, r1 = flow.advance(AuthContext(flow_id="tok-2"), _sub(password="secret"))
    store.save(ctx)
    # 模拟下一请求：从 store 取回上下文再推进
    reloaded = store.load("tok-2")
    ctx2, r2 = flow.advance(reloaded, _sub(step_id="otp", code="123"))
    assert r2.kind == "success"


# ----------------------------- actionable 死局 / owner 分流 / attempts / identity 端口 -----

def test_deadlock_terminates_as_failure():
    """applies_to 恒 False 的步骤 → 凭证满足后无可推进步骤 → deadlock → failure。"""
    class _PendingSms:
        step_id = "sms"; step_kind = "factor"; priority = 5
        def applies_to(self, c): return False
        def advance(self, c, s): return AuthStepResult(status="pending")
    class _Pwd:
        step_id = "password"; step_kind = "credential"; priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=1)
    f = AuthFlow({"password": _Pwd(), "sms": _PendingSms()},
                 AllOf([StepRef("password"), StepRef("sms")]),
                 trusted_step_ids=frozenset({"password"}))
    c = AuthContext(flow_id="f1")
    c, _ = f.advance(c, type("S", (), {"username": "a", "password": "b"})())
    c, r = f.advance(c, None)
    assert r.kind == "failure"


def test_non_builtin_user_id_dropped():
    """非受信步骤给出 user_id、已配 identity_resolver → 护栏拒绝，resolver 未调用。"""
    class _Imposter:
        step_id = "evil"; step_kind = "credential"; priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=1)
    called = {}
    f = AuthFlow({"evil": _Imposter()}, StepRef("evil"),
                 identity_resolver=lambda i: (called.setdefault("x", 1) or 99),
                 trusted_step_ids=frozenset())
    c, r = f.advance(AuthContext(flow_id="f2"), object())
    assert r.kind == "failure" and c.resolved_user_id is None and "x" not in called


def test_attempts_cap():
    """超过 max_attempts 后返回 failure（认证尝试次数超限）。"""
    class _PendingSms2:
        step_id = "sms"; step_kind = "factor"; priority = 5
        def applies_to(self, c): return False
        def advance(self, c, s): return AuthStepResult(status="pending")
    f = AuthFlow({"sms": _PendingSms2()}, StepRef("sms"), max_attempts=3)
    c = AuthContext(flow_id="f3")
    last = None
    for _ in range(5):
        c, last = f.advance(c, None)
    assert last.kind == "failure"


def test_legacy_no_resolver_accepts_user_id():
    """无 identity_resolver、step 不在 trusted → 内建模式仍接受 user_id。"""
    class _LegacyPwd:
        step_id = "password"; step_kind = "credential"; priority = 0
        def applies_to(self, c): return c.resolved_user_id is None
        def advance(self, c, s): return AuthStepResult(status="satisfied", user_id=7)
    f = AuthFlow({"password": _LegacyPwd()}, StepRef("password"))  # 无 trusted、无 resolver
    c, r = f.advance(AuthContext(flow_id="lg"), object())
    assert r.kind == "success" and c.resolved_user_id == 7


def test_step_advance_exception_is_failsafe():
    """抛异常的 step 不得让引擎崩溃；应作 failed 处理→流程 failure（spec 不变量⑤）。"""
    class _Boom:
        step_id = "boom"; step_kind = "credential"; priority = 0
        def applies_to(self, c): return True
        def advance(self, c, s): raise RuntimeError("boom")
    f = AuthFlow({"boom": _Boom()}, StepRef("boom"))
    c, r = f.advance(AuthContext(flow_id="bx"), object())
    assert r.kind == "failure"   # 不抛、不崩溃
