# -*- coding: utf-8 -*-
"""
SSO 登录流程（app.helper.sso）回归：G3 样板下沉后的统一编排与安全不变量。

complete_login 现承载每个 SSO 插件原本重复的逻辑（state/换身份/用户解析建号/铸票），
以 mock 替换 UserOper / 票据 / 密码散列，只验证编排与安全门。
"""
from unittest import TestCase
from unittest.mock import patch

from app.core.sso import AuthProviderIdentity, issue_state
from app.helper import sso as sso_helper


class _Provider:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"

    def __init__(self, identity=None, raise_fetch=False):
        self._identity = identity
        self._raise = raise_fetch

    def authorize_url(self, state, redirect_uri):
        return f"https://idp.example.com/auth?state={state}&redirect_uri={redirect_uri}"

    def fetch_identity(self, code, redirect_uri):
        if self._raise:
            raise RuntimeError("boom")
        return self._identity


class _User:
    def __init__(self, uid=1, name="sso_github_octocat", is_active=True):
        self.id = uid
        self.name = name
        self.is_active = is_active


def _identity(username="octocat", subject="sub-1"):
    return AuthProviderIdentity(subject=subject, username=username, avatar="a")


class BeginLoginTest(TestCase):

    def test_begin_login_issues_state_in_authorize_url(self):
        url = sso_helper.begin_login(_Provider(), "https://mp.example.com/cb")
        self.assertIn("https://idp.example.com/auth?state=", url)
        # 签发的 state 应能被随后的 consume 接受（单次）
        state = url.split("state=")[1].split("&")[0]
        self.assertTrue(sso_helper.sso_core.consume_state(state))


class CompleteLoginTest(TestCase):

    def test_invalid_state_blocks_before_fetch(self):
        prov = _Provider(identity=_identity())
        with patch.object(_Provider, "fetch_identity", side_effect=AssertionError("不应被调用")):
            ticket, error = sso_helper.complete_login(prov, "code", "forged-state", "cb")
        self.assertIsNone(ticket)
        self.assertEqual(error, "invalid_state")

    def test_invalid_code_rejected(self):
        prov = _Provider(identity=_identity())
        ticket, error = sso_helper.complete_login(prov, "bad\ncode", issue_state(), "cb")
        self.assertEqual((ticket, error), (None, "invalid_code"))

    def test_fetch_identity_none(self):
        prov = _Provider(identity=None)
        ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), (None, "fetch_identity_failed"))

    def test_fetch_identity_raises_is_safe(self):
        prov = _Provider(raise_fetch=True)
        ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), (None, "fetch_identity_failed"))

    def test_bound_identity_mints_ticket(self):
        # 已绑定身份：按 (provider_id, subject) 命中绑定 → 返回绑定用户、铸票（改名安全：不查用户名）
        prov = _Provider(identity=_identity(username="renamed-login", subject="42"))
        binding = type("B", (), {"user_id": 7})()
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.User") as U, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK") as mint:
            SI.get_by_subject.return_value = binding
            U.get.return_value = _User(uid=7)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), ("TK", None))
        SI.get_by_subject.assert_called_with(db=None, provider_id="github", subject="42")
        self.assertEqual(mint.call_args.kwargs["user_id"], 7)
        self.assertEqual(mint.call_args.kwargs["provider_id"], "github")

    def test_unbound_without_auto_create(self):
        prov = _Provider(identity=_identity(subject="99"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            SI.get_by_subject.return_value = None
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=False)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        UO.return_value.add.assert_not_called()
        mint.assert_not_called()

    def test_auto_create_makes_non_superuser_and_binds(self):
        # 未绑定 + auto_create：建非管理员用户（用户名由 subject 派生）+ 落 SsoIdentity 绑定
        prov = _Provider(identity=_identity(username="newbie", subject="123"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK"), \
                patch("app.helper.sso.get_password_hash", return_value="hashed"):
            SI.get_by_subject.return_value = None
            UO.return_value.get_by_name.side_effect = [None, _User(uid=9, name="sso_github_123")]
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), ("TK", None))
        kw = UO.return_value.add.call_args.kwargs
        self.assertEqual(kw["name"], "sso_github_123")          # 用户名由稳定 subject 派生
        self.assertFalse(kw["is_superuser"], "自动建号不得为管理员")
        self.assertTrue(kw["is_active"])
        self.assertEqual(kw["hashed_password"], "hashed")
        SI.assert_called_once()                                 # 落了绑定
        bkw = SI.call_args.kwargs
        self.assertEqual((bkw["provider_id"], bkw["subject"], bkw["user_id"]), ("github", "123", 9))
        SI.return_value.create.assert_called_once()

    def test_auto_create_reuses_sso_managed_residual_user(self):
        # 同名残留用户且确为 SSO 托管账号（有绑定）+ 未禁用 → 复用，不重复建号
        prov = _Provider(identity=_identity(subject="77"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK"):
            SI.get_by_subject.return_value = None
            SI.list_by_user.return_value = [object()]            # 确为 SSO 托管账号
            UO.return_value.get_by_name.return_value = _User(uid=3, name="sso_github_77")
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), ("TK", None))
        UO.return_value.add.assert_not_called()

    def test_residual_disabled_user_not_reused(self):
        # B-4：同名残留用户被禁用 → 拒绝复用（防绕过封禁）
        prov = _Provider(identity=_identity(subject="78"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            SI.get_by_subject.return_value = None
            UO.return_value.get_by_name.return_value = _User(uid=3, is_active=False)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        SI.list_by_user.assert_not_called()
        mint.assert_not_called()

    def test_residual_non_sso_user_not_taken_over(self):
        # C-1：同名残留用户无任何身份绑定（非 SSO 本地账号）→ 拒绝接管
        prov = _Provider(identity=_identity(subject="79"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            SI.get_by_subject.return_value = None
            SI.list_by_user.return_value = []                    # 无绑定 → 非 SSO 账号
            UO.return_value.get_by_name.return_value = _User(uid=3, name="sso_github_79")
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        UO.return_value.add.assert_not_called()
        mint.assert_not_called()

    def test_degenerate_subject_rejected(self):
        # A-3：纯分隔符 subject（无字母数字）被拒
        for bad in ("...", "---", ".-_"):
            prov = _Provider(identity=_identity(subject=bad))
            with patch("app.helper.sso.SsoIdentity") as SI:
                ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
            self.assertEqual((ticket, error), (None, "user_not_provisioned"), f"应拒绝 subject={bad}")
            SI.get_by_subject.assert_not_called()

    def test_concurrent_binding_conflict_reuses_existing(self):
        # 并发首登：落绑定唯一键冲突 → 复用已存在绑定用户，不 500
        prov = _Provider(identity=_identity(subject="88"))
        existing = type("B", (), {"user_id": 4})()
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.User") as U, \
                patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK") as mint:
            SI.get_by_subject.side_effect = [None, existing]      # 首查未绑定，冲突后再查命中
            SI.return_value.create.side_effect = Exception("UNIQUE")
            UO.return_value.get_by_name.side_effect = [None, _User(uid=4)]
            U.get.return_value = _User(uid=4)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), ("TK", None))
        self.assertEqual(mint.call_args.kwargs["user_id"], 4)

    def test_disabled_bound_user_rejected(self):
        prov = _Provider(identity=_identity(subject="55"))
        binding = type("B", (), {"user_id": 5})()
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.User") as U, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            SI.get_by_subject.return_value = binding
            U.get.return_value = _User(uid=5, is_active=False)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        mint.assert_not_called()

    def test_malformed_subject_rejected(self):
        # 安全：非法 subject 在任何绑定查询/建号之前被拒
        prov = _Provider(identity=_identity(subject="bad/../x"))
        with patch("app.helper.sso.SsoIdentity") as SI, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        SI.get_by_subject.assert_not_called()
        mint.assert_not_called()
