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


def _identity(username="octocat"):
    return AuthProviderIdentity(subject="sub-1", username=username, avatar="a")


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

    def test_existing_user_mints_ticket_with_namespaced_name(self):
        prov = _Provider(identity=_identity("octocat"))
        with patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK") as mint:
            UO.return_value.get_by_name.return_value = _User(uid=7)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), ("TK", None))
        UO.return_value.get_by_name.assert_called_with(name="sso_github_octocat")  # 提供方+前缀双重隔离
        self.assertEqual(mint.call_args.kwargs["user_id"], 7)
        self.assertEqual(mint.call_args.kwargs["provider_id"], "github")

    def test_not_provisioned_without_auto_create(self):
        prov = _Provider(identity=_identity("stranger"))
        with patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            UO.return_value.get_by_name.return_value = None
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=False)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        UO.return_value.add.assert_not_called()
        mint.assert_not_called()

    def test_auto_create_makes_non_superuser(self):
        prov = _Provider(identity=_identity("newbie"))
        with patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket", return_value="TK"), \
                patch("app.helper.sso.get_password_hash", return_value="hashed"):
            UO.return_value.get_by_name.side_effect = [None, _User(uid=9, name="sso_github_newbie")]
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), ("TK", None))
        kw = UO.return_value.add.call_args.kwargs
        self.assertEqual(kw["name"], "sso_github_newbie")
        self.assertFalse(kw["is_superuser"], "自动建号不得为管理员")
        self.assertTrue(kw["is_active"])
        self.assertEqual(kw["hashed_password"], "hashed")

    def test_disabled_user_rejected(self):
        prov = _Provider(identity=_identity("banned"))
        with patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            UO.return_value.get_by_name.return_value = _User(name="sso_github_banned", is_active=False)
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb")
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        mint.assert_not_called()

    def test_malformed_external_username_rejected(self):
        prov = _Provider(identity=_identity("evil/../admin"))
        with patch("app.helper.sso.UserOper") as UO, \
                patch("app.helper.sso.create_plugin_auth_ticket") as mint:
            ticket, error = sso_helper.complete_login(prov, "c", issue_state(), "cb", auto_create=True)
        self.assertEqual((ticket, error), (None, "user_not_provisioned"))
        UO.return_value.get_by_name.assert_not_called()
        mint.assert_not_called()
