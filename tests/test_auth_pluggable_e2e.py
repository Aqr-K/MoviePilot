# -*- coding: utf-8 -*-
"""
PR7 端到端证明 + 参考实现：自包含的示例主认证 provider（目录型，如 LDAP）与示例 MFA 第二因子
（SMS 挑战-应答），注册到**全局注册表**后跑与 live 登录同一套框架函数，证明分类矩阵里两个原本
为空的格子（D2 本地目录 / D1 持有-SMS）**零 core 改动**即可由插件转绿，并验证按 owner 卸载干净。

这两个 Example 类同时是插件作者的可复制参考：生产实现只需把 _directory / _store 换成真实
LDAP 绑定 / 短信网关，契约不变。
"""
import types

from app.core.auth.credentials import (
    all_credential_providers,
    register_credential_provider,
    unregister_credential_providers,
)
from app.core.auth.mfa_factors import (
    MfaChallengeHint,
    MfaSubmission,
    MfaUserRef,
    get_mfa_factor,
    register_mfa_factor,
    unregister_mfa_factors,
)
from app.core.auth.outcome import CredentialOutcome, MfaFactorResult
from app.core.challenge_store import ChallengeStore
from app.service.auth.orchestrator import enrolled_factor_ids, evaluate_mfa, try_credential_providers
from app.service.auth.provisioning import ProvisioningDeps

OWNER = "ex-auth-plugin"


# ----------------------------- 参考实现：目录型主认证 provider -----------------------------
class ExampleLdapCredentialProvider:
    """参考：目录型主认证（LDAP/AD）。生产把 _directory 换成真实目录绑定即可，契约不变。"""

    provider_id = "ldap-example"
    factor_kind = "directory"
    priority = 50
    auto_create = True

    def __init__(self, directory):
        self._directory = directory  # {username: password}

    def applies_to(self, req):
        return req.grant_type == "password" and bool(req.username) and bool(req.password)

    def verify_credentials(self, req):
        if req.username not in self._directory:
            return CredentialOutcome(status="not_mine")
        if self._directory[req.username] != req.password:
            return CredentialOutcome(status="reject")
        return CredentialOutcome(status="success", username=req.username,
                                 extra={"subject": req.username})


# ----------------------------- 参考实现：SMS 挑战-应答第二因子 -----------------------------
class ExampleSmsFactor:
    """参考：SMS OTP 第二因子（挑战-应答）。challenge_hint 模拟"发码并存挑战"，verify 校验后消费。"""

    factor_id = "sms-example"
    factor_kind = "possession"
    display_name = "短信验证码"
    priority = 30

    def __init__(self, enrolled_users, store):
        self._enrolled = enrolled_users  # set[user_id]
        self._store = store              # ChallengeStore

    def _key(self, ref):
        return f"{ref.user_id}:{self.factor_id}"

    def is_enrolled(self, ref):
        return ref.user_id in self._enrolled

    def challenge_hint(self, ref):
        # 模拟下发短信验证码并存入挑战（生产此处调用短信网关）
        self._store.put(self._key(ref), {"code": "246810"})
        return MfaChallengeHint(self.factor_id, self.factor_kind, self.display_name,
                                challenge={"delivery": "sms", "sent": True})

    def verify(self, ref, submission):
        data = self._store.get(self._key(ref))
        if data and submission.code and submission.code == data.get("code"):
            self._store.consume(self._key(ref))
            return MfaFactorResult(status="allow")
        return MfaFactorResult(status="deny")


# ----------------------------- 测试夹具 -----------------------------
def _ok_deps(created_user):
    state = {"created": False}
    return ProvisioningDeps(
        get_binding=lambda p, s: None,
        get_user_by_id=lambda uid: created_user,
        get_user_by_name=lambda n: created_user if state["created"] else None,
        create_user=lambda name, avatar=None: state.__setitem__("created", True),
        list_bindings_for_user=lambda uid: [],
        create_binding=lambda **kw: None,
    )


def _creds(username, password):
    return types.SimpleNamespace(grant_type="password", username=username,
                                 password=password, code=None, mfa_code=None)


# ----------------------------- 端到端证明 -----------------------------
def test_ldap_credential_provider_cell_goes_green_zero_core_change():
    """D2 本地目录格：注册示例目录 provider → try_credential_providers（全局注册表）解析/建号。"""
    prov = ExampleLdapCredentialProvider({"alice": "secret"})
    ok, reason = register_credential_provider(prov, owner=OWNER)
    assert ok, reason
    try:
        created = types.SimpleNamespace(id=500, is_active=True)
        deps = _ok_deps(created)
        # 正确凭证 → 成功解析（经守护式 provisioning 建号）
        res = try_credential_providers(_creds("alice", "secret"), deps=deps)
        assert res is not None and res.user is created and res.apply_mfa is True
        # 错误密码 → reject → 拒绝（None）
        assert try_credential_providers(_creds("alice", "wrong"), deps=deps) is None
        # 非目录用户 → not_mine → 回落（None）
        assert try_credential_providers(_creds("bob", "x"), deps=deps) is None
    finally:
        unregister_credential_providers(owner=OWNER)
    assert all(p.provider_id != "ldap-example" for p in all_credential_providers())


def test_sms_factor_cell_goes_green_zero_core_change():
    """D1 持有-SMS 格：注册示例 SMS 因子 → evaluate_mfa 走挑战-应答。"""
    store = ChallengeStore()
    factor = ExampleSmsFactor(enrolled_users={7}, store=store)
    ok, reason = register_mfa_factor(factor, owner=OWNER)
    assert ok, reason
    try:
        ref = MfaUserRef(user_id=7, username="carol")
        factor.challenge_hint(ref)  # 模拟发码
        # 未提供码 → mfa_required（列出因子）
        r1 = evaluate_mfa(ref, MfaSubmission(code=None), [factor])
        assert r1.kind == "mfa_required" and "sms-example" in r1.factors_available
        # 正确码 → success
        r2 = evaluate_mfa(ref, MfaSubmission(factor_id="sms-example", code="246810"), [factor])
        assert r2.kind == "success"
        # 未注册该因子的用户 → 放行
        assert evaluate_mfa(MfaUserRef(user_id=999, username="dave"),
                            MfaSubmission(code=None), [factor]).kind == "success"
    finally:
        unregister_mfa_factors(owner=OWNER)
    assert get_mfa_factor("sms-example") is None


def test_plugin_factor_appears_in_live_enumeration(monkeypatch):
    """证明 live 枚举路径（enrolled_factor_ids → factors_for_user → 全局注册表）能看到插件因子。"""
    import app.db.models.passkey as pk
    import app.utils.otp as otp
    monkeypatch.setattr(pk.PassKey, "get_by_user_id",
                        staticmethod(lambda db=None, user_id=None: []))
    monkeypatch.setattr(otp.OtpUtils, "check", staticmethod(lambda s, p: False))

    factor = ExampleSmsFactor(enrolled_users={7}, store=ChallengeStore())
    register_mfa_factor(factor, owner=OWNER)
    try:
        user = types.SimpleNamespace(id=7, name="carol", is_otp=False, otp_secret="S")
        # 内建因子均未启用（is_otp=False, 无 passkey）→ 仅插件 SMS 因子已注册
        assert enrolled_factor_ids(user) == ["sms-example"]
    finally:
        unregister_mfa_factors(owner=OWNER)
