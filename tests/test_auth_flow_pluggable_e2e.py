# -*- coding: utf-8 -*-
"""PR12：多步状态机端到端证明 —— 插件件经**现有 SPI** 注册后，零 core 改动地驱动多步登录流程。

证明：
  1. 插件目录 provider（LDAP 类）+ 插件 SMS 挑战因子注册到全局注册表后，FlowService 端到端
     完成"凭证回落 → 条件 MFA → 多轮挑战-应答 → 成功铸 Token"；
  2. 任意组合：注入 N-of-M（2/3）策略即得强 MFA 多步流程；
均不改动任何 core/服务代码，仅复用 register_credential_provider / register_mfa_factor 公共 SPI。
"""
import types

from app.core.auth.credentials import (
    all_credential_providers,
    register_credential_provider,
    unregister_credential_providers,
)
from app.core.auth.flow import NOf, StepRef
from app.core.auth.mfa_factors import (
    MfaChallengeHint,
    all_mfa_factors,
    register_mfa_factor,
    unregister_mfa_factors,
)
from app.core.auth.outcome import CredentialOutcome, MfaFactorResult
from app.core.challenge_store import ChallengeStore
from app.service.auth.builtin_factors import OtpFactor
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_service import FlowService
from app.service.auth.flow_steps import CredentialProviderStep, FactorStep, PasswordStep
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
    assert register_credential_provider(provider, owner=OWNER)[0]
    assert register_mfa_factor(sms, owner=OWNER)[0]
    try:
        created = types.SimpleNamespace(id=500, name="sso_ldap-flow_alice", is_active=True)
        deps = _deps(created)
        credential_steps = [PasswordStep(authenticate=lambda u, p: None)] + [
            CredentialProviderStep(p, deps=deps)
            for p in all_credential_providers() if p.provider_id == "ldap-flow"
        ]
        svc = FlowService(
            flow_store=FlowStore(),
            credential_steps=credential_steps,
            factor_steps_for=lambda user: [FactorStep(f) for f in all_mfa_factors()
                                           if f.factor_id == "sms-flow"],
            load_user=lambda uid: created if uid == 500 else None,
            issue_token=lambda user: {"access_token": "TK", "user_id": user.id},
        )
        # 1) 凭证：本地密码不符 → 回落插件 LDAP provider → 解析建号 → 需 SMS
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
        unregister_credential_providers(owner=OWNER)
        unregister_mfa_factors(owner=OWNER)
    # 卸载干净
    assert all(p.provider_id != "ldap-flow" for p in all_credential_providers())
    assert all(f.factor_id != "sms-flow" for f in all_mfa_factors())


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
