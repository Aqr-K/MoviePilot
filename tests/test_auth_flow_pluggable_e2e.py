# -*- coding: utf-8 -*-
"""多步状态机端到端证明 —— 插件件经**统一 SPI**（``register_auth_step`` / ``provides_auth_steps``）
注册后，零 core 改动地驱动多步登录流程。

证明：
  1. 插件目录 provider（LDAP 类，包装为 ``CredentialProviderStep``）+ 插件 SMS 挑战因子（包装为
     ``FactorStep``）经 ``register_auth_step`` 注册到**全局步骤注册表**后，FlowService 端到端完成
     "凭证回落 → 条件 MFA → 多轮挑战-应答 → 成功铸 Token"；
  2. 任意组合：注入 N-of-M（2/3）策略即得强 MFA 多步流程；
均不改动任何 core/服务代码，仅复用 ``register_auth_step`` / ``all_auth_steps`` 统一步骤 SPI
（credential/factor 统一为单 Step 模型）。
"""
import types

from app.core.auth.flow import NOf, StepRef
from app.core.auth.outcome import CredentialOutcome, MfaFactorResult
from app.core.auth.steps import (
    all_auth_steps,
    register_auth_step,
    unregister_auth_steps,
)
from app.core.auth.types import MfaChallengeHint
from app.core.challenge_store import ChallengeStore
from app.service.auth.builtin_factors import OtpFactor
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_service import FlowService
from app.service.auth.flow_steps import (
    CredentialProviderStep,
    FactorStep,
    PasswordStep,
    make_identity_resolver,
)
from app.service.auth.provisioning import ProvisioningDeps

OWNER = "ex-flow-plugin"


def _sub(**kw):
    return types.SimpleNamespace(**kw)


# ----------------------------- 参考实现：插件件 -----------------------------
class ExampleLdapProvider:
    provider_id = "ldap-flow"
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


class ExampleSmsFactor:
    factor_id = "sms-flow"
    factor_kind = "possession"
    display_name = "短信验证码"
    priority = 30

    def __init__(self, enrolled_users, store):
        self._enrolled = enrolled_users
        self._store = store

    def _key(self, ref):
        return f"{ref.user_id}:{self.factor_id}"

    def is_enrolled(self, ref):
        return ref.user_id in self._enrolled

    def challenge_hint(self, ref):
        self._store.put(self._key(ref), {"code": "246810"})
        return MfaChallengeHint(self.factor_id, self.factor_kind, self.display_name,
                                challenge={"delivery": "sms", "sent": True})

    def verify(self, ref, submission):
        data = self._store.get(self._key(ref))
        if data and submission.code and submission.code == data.get("code"):
            self._store.consume(self._key(ref))
            return MfaFactorResult(status="allow")
        return MfaFactorResult(status="deny")


def _deps(created_user):
    state = {"created": False}
    return ProvisioningDeps(
        get_binding=lambda p, s: None,
        get_user_by_id=lambda uid: created_user,
        get_user_by_name=lambda n: created_user if state["created"] else None,
        create_user=lambda name, avatar=None: state.__setitem__("created", True),
        list_bindings_for_user=lambda uid: [],
        create_binding=lambda **kw: None,
    )


# ----------------------------- 端到端：LDAP + SMS 多轮挑战 -----------------------------
def test_plugin_ldap_then_sms_challenge_end_to_end_zero_core_change():
    provider = ExampleLdapProvider({"alice": "secret"})
    store = ChallengeStore()
    sms = ExampleSmsFactor(enrolled_users={500}, store=store)
    created = types.SimpleNamespace(id=500, name="ext_ldap-flow_alice", is_active=True)
    deps = _deps(created)
    # 统一 SPI：把插件构件包装成 IAuthStep 后经 register_auth_step 注册到全局步骤注册表
    #（模拟 provides_auth_steps）；凭证步与因子步统一一条注册表，由装配桥按 step_kind 切分。
    assert register_auth_step(CredentialProviderStep(provider), owner=OWNER)[0]
    assert register_auth_step(FactorStep(sms), owner=OWNER)[0]
    try:
        steps = all_auth_steps()
        credential_steps = [PasswordStep(authenticate=lambda u, p: None)] + [
            s for s in steps
            if getattr(s, "step_kind", None) == "credential" and s.step_id == "ldap-flow"
        ]
        factor_steps = [s for s in steps
                        if getattr(s, "step_kind", None) == "factor" and s.step_id == "sms-flow"]
        svc = FlowService(
            flow_store=FlowStore(),
            credential_steps=credential_steps,
            factor_steps_for=lambda user: factor_steps,
            load_user=lambda uid: created if uid == 500 else None,
            issue_token=lambda user: {"access_token": "TK", "user_id": user.id},
            # 插件 LDAP 凭证步交回 identity，须经引擎注入的 resolver 落地（resolver 注入式解析）
            identity_resolver=make_identity_resolver(deps),
        )
        # 1) 凭证：本地密码不符 → 回落插件 LDAP 凭证步 → 解析建号 → 需 SMS
        out1 = svc.begin(_sub(grant_type="password", username="alice", password="secret"))
        assert out1["status"] == "mfa_required"
        assert out1["factors_available"] == ["sms-flow"]
        token = out1["flow_token"]
        # 2) 选 SMS 未带码 → 下发挑战（发码）
        out2 = svc.advance(token, _sub(step_id="sms-flow"))
        assert out2["status"] == "challenge"
        assert out2["challenge"]["sent"] is True
        # 3) 带正确码 → 成功铸 Token
        out3 = svc.advance(token, _sub(step_id="sms-flow", code="246810"))
        assert out3["status"] == "success"
        assert out3["token"]["access_token"] == "TK"
    finally:
        unregister_auth_steps(owner=OWNER)
    # 卸载干净（统一步骤注册表中不再残留插件凭证步 / 因子步）
    assert all(s.step_id != "ldap-flow" for s in all_auth_steps())
    assert all(s.step_id != "sms-flow" for s in all_auth_steps())


# ----------------------------- 端到端：N-of-M（2/3）强 MFA -----------------------------
def test_n_of_m_strong_mfa_end_to_end():
    user = types.SimpleNamespace(id=7, name="strong", is_active=True)
    f_a = FactorStep(OtpFactor(is_enrolled=lambda r: True, verify=lambda r, c: c == "1"), step_id="a")
    f_b = FactorStep(OtpFactor(is_enrolled=lambda r: True, verify=lambda r, c: c == "2"), step_id="b")
    f_c = FactorStep(OtpFactor(is_enrolled=lambda r: True, verify=lambda r, c: c == "3"), step_id="c")
    svc = FlowService(
        flow_store=FlowStore(),
        credential_steps=[PasswordStep(authenticate=lambda u, p: user if p == "pw" else None)],
        factor_steps_for=lambda u: [f_a, f_b, f_c],
        load_user=lambda uid: user,
        issue_token=lambda u: {"access_token": "TK2"},
        mfa_requirement=lambda steps: NOf(2, [StepRef(s.step_id) for s in steps]),
    )
    out = svc.begin(_sub(username="strong", password="pw"))
    assert out["status"] == "mfa_required" and set(out["factors_available"]) == {"a", "b", "c"}
    token = out["flow_token"]
    out = svc.advance(token, _sub(step_id="a", code="1"))
    assert out["status"] == "mfa_required" and set(out["factors_available"]) == {"b", "c"}  # 还差 1
    out = svc.advance(token, _sub(step_id="b", code="2"))
    assert out["status"] == "success" and out["token"]["access_token"] == "TK2"
