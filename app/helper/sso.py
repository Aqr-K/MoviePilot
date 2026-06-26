# -*- coding: utf-8 -*-
"""
SSO 登录发起（helper 层）。

承接 ``app.core.auth.redirect`` 的 db-free 核心（state/registry/contract）签发 CSRF state 并构造 IdP
授权页 URL。回调完成（换身份 / 解析建号 / 条件 MFA / 铸票）已**统一由流程引擎驱动**
（见 ``app.service.auth.sso_flow`` + ``/auth/sso/{id}/callback`` 端点的 ``RedirectStep``），不再在本 helper 重复。
"""
from app.core.auth import redirect as sso_core


def begin_login(provider, redirect_uri: str) -> str:
    """签发 CSRF state 并返回 IdP 授权页 URL（框架统一持有 state）。"""
    # flow_token="" is transitional; legacy begin path is replaced by RedirectStep in a later task.
    state = sso_core.issue_state(flow_token="", provider_id=getattr(provider, "provider_id", ""))
    return provider.authorize_url(state, redirect_uri)
