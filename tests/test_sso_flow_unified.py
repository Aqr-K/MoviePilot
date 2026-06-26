# -*- coding: utf-8 -*-
"""SSO 收敛进统一流程引擎（spec §5/§6 "先桥后删"）：

证明 SSO 不再走 ticket 旁路，而是与密码/因子**同一条** ``FlowService``：
  - ``/auth/flow/begin {flow:"<provider>"}`` → RedirectStep 自签 flow 绑定 state 并下发跳转挑战；
  - ``GET /auth/flow/callback`` 薄桥 → 消费一次 state 取回 flow_token → 回灌引擎推进（state_payload
    透传，RedirectStep 不二次消费）→ 解析身份 → 302 回前端（成功铸 ticket，flow_token 绝不入 URL）。

单元层另证：RedirectStep 收到 ``state_payload`` 时**不**二次消费；``_issue_redirect`` 签发的 state
绑定到 ``context.flow_id``。旧 ``/sso/*`` + ``sso_flow`` 路径不在本文件触碰（另文件保持绿）。
"""
import types
from urllib.parse import parse_qs, urlparse, urlencode

import pytest

from app.core.auth import redirect as sso


# --------------------------------------------------------------------------- 测试替身


class _StubIdp:
    """最小合法 SSO 提供方：authorize_url 把 state 透传进 URL，fetch_identity 返回固定外部身份。"""

    provider_id = "unifiedsso"
    provider_name = "Unified SSO"
    provider_icon = "mdi-login"
    priority = 100
    auto_create = True
    success_redirect = "/dashboard"

    def authorize_url(self, state, redirect_uri):
        return f"https://idp.example.com/authorize?{urlencode({'state': state, 'redirect_uri': redirect_uri})}"

    def fetch_identity(self, code, redirect_uri):
        return types.SimpleNamespace(subject="sso-42", username="ssouser", avatar=None)


def _build_request(path="/api/v1/auth/flow/begin", method="POST"):
    from fastapi import Request

    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"host", b"testserver")],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 123),
        "query_string": b"",
    })


def _state_from_authorize_url(url: str) -> str:
    return parse_qs(urlparse(url).query)["state"][0]


@pytest.fixture
def registered_idp():
    """把 stub 提供方注册进 redirect 注册表（owner 隔离），用例退出后卸载。"""
    provider = _StubIdp()
    sso.register_auth_provider(provider, owner="unifiedtest")
    try:
        yield provider
    finally:
        sso.unregister_auth_providers("unifiedtest")


@pytest.fixture
def no_emit(monkeypatch):
    """隔离观测事件系统（fire-and-forget 外部依赖）。"""
    from app.api.endpoints import auth as auth_module

    monkeypatch.setattr(auth_module, "emit_auth_event", lambda *a, **kw: None)


# --------------------------------------------------------------------------- S1：begin 下发跳转挑战


def test_flow_begin_sso_issues_redirect_challenge(registered_idp, no_emit):
    """begin {flow:"unifiedsso"} → status==challenge，redirect 挑战，authorize_url 含本 flow 绑定 state。"""
    from app.api.endpoints.auth import FlowBeginRequest, flow_begin

    result = flow_begin(FlowBeginRequest(flow="unifiedsso"), _build_request())

    assert result["status"] == "challenge"
    challenge = result["challenge"]
    assert challenge["kind"] == "redirect"
    assert challenge["provider_id"] == "unifiedsso"
    state = _state_from_authorize_url(challenge["authorize_url"])
    assert state  # 授权 URL 里带上了签发的 state

    # state 与本 flow + provider 绑定（消费一次即销毁）
    payload = sso.consume_state(state)
    assert payload == {"flow_token": result["flow_token"], "provider_id": "unifiedsso"}


# --------------------------------------------------------------------------- S1：callback 薄桥推进并 302


def _seed_callback_flow(monkeypatch, registered_idp, user=None):
    """跑一遍 begin 取回 (flow_token, state)，并把 DB 协作 stub 掉，供 callback 推进。"""
    from app.api.endpoints import auth as auth_module
    from app.api.endpoints.auth import FlowBeginRequest, flow_begin

    user = user or types.SimpleNamespace(id=42, name="ssouser", is_active=True,
                                         is_superuser=False, avatar=None, permissions={})
    # identity → 本地用户（owner-routing 端口落地）
    monkeypatch.setattr("app.service.auth.flow_steps.resolve_or_create",
                        lambda provider_id, **kw: user)
    fake_user = type("FakeUser", (), {"get": staticmethod(lambda db=None, rid=None, **kw: user)})
    monkeypatch.setattr(auth_module, "User", fake_user)

    begin = flow_begin(FlowBeginRequest(flow="unifiedsso"), _build_request())
    state = _state_from_authorize_url(begin["challenge"]["authorize_url"])
    return begin["flow_token"], state


def test_flow_callback_advances_and_redirects(registered_idp, no_emit, monkeypatch):
    """seed 一条已签发 state 的 flow → GET /auth/flow/callback → 302；state 消费一次；flow_token 不入 URL。"""
    from app.api.endpoints import auth as auth_module
    from fastapi.responses import RedirectResponse

    # 无内建因子 → 解析后直接成功（铸 ticket）
    monkeypatch.setattr(auth_module, "_builtin_factor_steps", lambda user: [])
    flow_token, state = _seed_callback_flow(monkeypatch, registered_idp)

    resp = auth_module.flow_callback(
        _build_request(path="/api/v1/auth/flow/callback", method="GET"),
        code="good-code", state=state)

    assert isinstance(resp, RedirectResponse)
    location = resp.headers["location"]
    assert "ticket=" in location               # 成功铸一次性 ticket 交浏览器
    assert flow_token not in location          # flow_token 绝不出现在 302 URL
    assert "flow_token=" not in location
    # state 在薄桥已消费一次；RedirectStep 未二次消费 → 此时已不可再消费
    assert sso.consume_state(state) is None


def test_flow_callback_invalid_state(no_emit):
    """未知 state → 302 带 sso_error（绝不推进流程）。"""
    from app.api.endpoints import auth as auth_module
    from fastapi.responses import RedirectResponse

    resp = auth_module.flow_callback(
        _build_request(path="/api/v1/auth/flow/callback", method="GET"),
        code="x", state="totally-unknown-state")

    assert isinstance(resp, RedirectResponse)
    assert "sso_error=invalid_state" in resp.headers["location"]


# --------------------------------------------------------------------------- 单元：consume-once 与 state 绑定


class _FetchIdp:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"
    priority = 100
    auto_create = True

    def authorize_url(self, state, redirect_uri):
        return f"https://idp/x?state={state}"

    def fetch_identity(self, code, redirect_uri):
        return types.SimpleNamespace(subject="42", username="octo", avatar=None)


def test_redirect_step_with_state_payload_does_not_reconsume():
    """收到预消费的 state_payload → RedirectStep 绝不再调 consume_state（避免双消费）。"""
    from app.core.auth.flow import AuthContext
    from app.service.auth.flow_steps import RedirectStep

    calls = []

    def _spy_consume(state):
        calls.append(state)
        return None  # 若被调用则会令校验失败，凸显回归

    step = RedirectStep(_FetchIdp(), consume_state=_spy_consume)
    sub = types.SimpleNamespace(code="good-code", state="raw-state",
                                state_payload={"flow_token": "f1", "provider_id": "github"},
                                redirect_uri="http://cb")
    result = step.advance(AuthContext(flow_id="f1"), sub)

    assert calls == []                       # 透传载荷 → 未二次消费
    assert result.status == "satisfied"
    assert result.identity.subject == "42"


def test_redirect_step_issue_redirect_binds_state_to_flow():
    """无授权码 → 签发与 context.flow_id 绑定的 state，并据其构造授权 URL。"""
    from app.core.auth.flow import AuthContext
    from app.service.auth.flow_steps import RedirectStep

    issued = []

    def _spy_issue(flow_token, provider_id):
        issued.append((flow_token, provider_id))
        return "STATE-123"

    step = RedirectStep(_FetchIdp(), issue_state=_spy_issue, redirect_uri="http://cb")
    result = step.advance(AuthContext(flow_id="FLOW-9"), types.SimpleNamespace(code=None))

    assert result.status == "challenge"
    assert "STATE-123" in result.challenge.authorize_url
    assert issued == [("FLOW-9", "github")]  # state 绑定到本 flow + provider
