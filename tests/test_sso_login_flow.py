# -*- coding: utf-8 -*-
"""
SSO 登录发起（``app.helper.sso.begin_login``）回归：签发的 state 应内嵌于授权 URL 且可被随后单次消费。

回调完成路径已统一由流程引擎驱动（``RedirectStep`` + ``FlowService``），其行为与安全护栏覆盖见：
``test_auth_flow_steps.py``（RedirectStep 双模 + 边界）、``test_sso_flow.py``（SSO 经 flow 接条件 MFA）、
``test_auth_provisioning.py``（C-1/B-4/并发等护栏的单一来源 ``resolve_or_create``）。
"""
from unittest import TestCase

from app.helper import sso as sso_helper


class _Provider:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"

    def authorize_url(self, state, redirect_uri):
        return f"https://idp.example.com/auth?state={state}&redirect_uri={redirect_uri}"


class BeginLoginTest(TestCase):

    def test_begin_login_issues_state_in_authorize_url(self):
        url = sso_helper.begin_login(_Provider(), "https://mp.example.com/cb")
        self.assertIn("https://idp.example.com/auth?state=", url)
        # 签发的 state 应能被随后的 consume 接受（单次有效）
        state = url.split("state=")[1].split("&")[0]
        self.assertTrue(sso_helper.sso_core.consume_state(state))
