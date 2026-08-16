# -*- coding: utf-8 -*-
"""
GitHub SSO 参考插件（框架版）回归。

插件只实现 IAuthProvider 的两件 IdP 特定事——本测试只验证这两件 + provides_auth_providers 注册；
框架侧流程（CSRF state / ExternalIdentity 绑定 / 铸票 / 重定向）由
test_auth_provider_registration 覆盖，不在此重复。
"""
from unittest import TestCase
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from app.core.auth.redirect import verify_auth_provider_contract
from app.plugins.githubsso import GithubAuthProvider, GithubSSO


def _fake_resp(payload):
    r = MagicMock()
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


def _provider(**kw):
    return GithubAuthProvider(client_id="cid", client_secret="sec", **kw)


class GithubSSOPluginTest(TestCase):

    def test_provides_nothing_until_configured(self):
        p = GithubSSO()
        self.assertEqual(p.provides_auth_providers(), [])           # 未配置 → 不注册
        p.init_plugin({"enabled": True, "client_id": "cid", "client_secret": "sec",
                       "auto_create": True, "success_redirect": "/dashboard"})
        provs = p.provides_auth_providers()
        self.assertEqual(len(provs), 1)
        prov = provs[0]
        self.assertEqual(prov.provider_id, "github")
        self.assertTrue(prov.auto_create)                           # 框架按 getattr 读取
        self.assertEqual(prov.success_redirect, "/dashboard")

    def test_provider_satisfies_contract(self):
        ok, reasons = verify_auth_provider_contract(_provider())
        self.assertTrue(ok, reasons)

    def test_authorize_url(self):
        url = _provider().authorize_url("STATE123", "https://mp.example.com/api/v1/auth/flow/callback")
        self.assertTrue(url.startswith("https://github.com/login/oauth/authorize?"))
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        self.assertEqual(q["client_id"], "cid")
        self.assertEqual(q["state"], "STATE123")
        self.assertEqual(q["redirect_uri"], "https://mp.example.com/api/v1/auth/flow/callback")

    def test_fetch_identity_uses_numeric_id_as_subject(self):
        # 关键：subject = GitHub 数字 id（稳定，改名不变），username = login（仅快照）
        with patch("app.plugins.githubsso.requests") as req:
            req.post.return_value = _fake_resp({"access_token": "tok"})
            req.get.return_value = _fake_resp(
                {"id": 583231, "login": "octocat", "avatar_url": "a", "name": "The Octocat"})
            ident = _provider().fetch_identity("code", "cb")
        self.assertIsNotNone(ident)
        self.assertEqual(ident.subject, "583231")
        self.assertEqual(ident.username, "octocat")
        self.assertEqual(ident.avatar, "a")
        self.assertEqual(ident.display_name, "The Octocat")

    def test_fetch_identity_no_access_token(self):
        with patch("app.plugins.githubsso.requests") as req:
            req.post.return_value = _fake_resp({})
            self.assertIsNone(_provider().fetch_identity("code", "cb"))

    def test_fetch_identity_missing_user_fields(self):
        with patch("app.plugins.githubsso.requests") as req:
            req.post.return_value = _fake_resp({"access_token": "tok"})
            req.get.return_value = _fake_resp({"login": "x"})       # 缺 id → 拒绝
            self.assertIsNone(_provider().fetch_identity("code", "cb"))

    def test_fetch_identity_network_error_is_safe(self):
        with patch("app.plugins.githubsso.requests") as req:
            req.post.side_effect = RuntimeError("network")
            self.assertIsNone(_provider().fetch_identity("code", "cb"))
