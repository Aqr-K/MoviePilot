import asyncio
import io
import inspect
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app.api.endpoints import login as login_endpoint
from app.api.endpoints import plugin as plugin_endpoint
from app.api.endpoints import system as system_endpoint
from app.api.endpoints import user as user_endpoint
from app.api.endpoints import dashboard as dashboard_endpoint
from app.core.security import verify_resource_token
from app.db.user_oper import (
    get_current_active_superuser,
    get_current_active_superuser_async,
    get_current_active_user_async,
)
from app.schemas.types import SystemConfigKey


def _dependency_of(func, parameter_name: str):
    """读取 FastAPI 函数参数上声明的依赖函数。"""
    return inspect.signature(func).parameters[parameter_name].default.dependency


def _build_request() -> Request:
    """构造最小测试请求。"""
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/login/access-token",
            "headers": [(b"host", b"testserver")],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 123),
        }
    )


def test_system_sensitive_read_endpoints_require_superuser():
    """系统敏感读取接口必须只允许管理员访问。"""
    assert _dependency_of(system_endpoint.get_env_setting, "_") is get_current_active_superuser_async
    assert _dependency_of(system_endpoint.get_setting, "_") is get_current_active_superuser_async


def test_system_public_read_endpoints_require_active_user():
    """公开读取接口只要求登录且启用的用户。"""
    assert _dependency_of(system_endpoint.ping, "_") is get_current_active_user_async
    assert _dependency_of(system_endpoint.get_public_setting, "_") is get_current_active_user_async


def test_dashboard_endpoints_require_superuser():
    """仪表板页面相关接口必须只允许管理员访问。"""
    assert _dependency_of(dashboard_endpoint.statistic, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.storage, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.processes, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.downloader, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.schedule, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.transfer, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.cpu, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.memory, "_") is get_current_active_superuser
    assert _dependency_of(dashboard_endpoint.network, "_") is get_current_active_superuser


def test_plugin_dashboard_endpoints_require_superuser():
    """插件仪表板接口必须只允许管理员访问。"""
    assert _dependency_of(plugin_endpoint.plugin_dashboard_meta, "_") is get_current_active_superuser
    assert _dependency_of(plugin_endpoint.plugin_dashboard_by_key, "_") is get_current_active_superuser
    assert _dependency_of(plugin_endpoint.plugin_dashboard, "_") is get_current_active_superuser


def test_system_public_setting_allows_only_non_sensitive_keys(monkeypatch):
    """公开系统设置接口只能读取明确列入白名单的非敏感配置。"""
    calls = []

    class FakeSystemConfigOper:
        """返回测试配置值的系统配置桩。"""

        def get(self, key):
            """返回测试配置值。"""
            calls.append(key)
            return [{"path": "/downloads"}]

    monkeypatch.setattr(system_endpoint, "SystemConfigOper", FakeSystemConfigOper)

    response = asyncio.run(
        system_endpoint.get_public_setting(SystemConfigKey.Directories.value)
    )

    assert response.success is True
    assert response.data == {"value": [{"path": "/downloads"}]}
    assert calls == [SystemConfigKey.Directories]

    response = asyncio.run(system_endpoint.get_public_setting("PLUGIN_MARKET"))

    assert response.success is True
    assert response.data == {"value": system_endpoint.settings.PLUGIN_MARKET}
    assert calls == [SystemConfigKey.Directories]

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(system_endpoint.get_public_setting("API_TOKEN"))

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "配置项不存在"


def test_system_ping_returns_success():
    """服务存活检测接口返回标准成功响应。"""
    response = asyncio.run(system_endpoint.ping())

    assert response.success is True


def test_login_sets_resource_token_cookie(monkeypatch):
    """登录成功时应立即写入资源 Cookie，避免插件静态文件抢先加载失败。（引擎驱动路径）"""
    from app import schemas

    fake_token = schemas.Token(
        access_token="test.jwt.token",
        token_type="bearer",
        super_user=False,
        user_id=1,
        user_name="user",
        avatar="",
        level=1,
        permissions={"discovery": True},
        wizard=False,
    )

    class FakeService:
        """返回登录成功结果的流程服务桩。"""

        def run_sync(self, submission):
            """返回成功结果。"""
            return {"status": "success", "token": fake_token}

    form_data = SimpleNamespace(username="user", password="password")
    request = _build_request()
    response = Response()

    monkeypatch.setattr(login_endpoint, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda result, username, ip: None)

    token = login_endpoint.login_access_token(
        request=request,
        response=response,
        form_data=form_data,
    )

    assert token.user_id == 1
    assert token.permissions == {"discovery": True}
    assert "set-cookie" in response.headers

    resource_cookie = response.headers["set-cookie"].split("=", 1)[1].split(";", 1)[0]
    payload = verify_resource_token(resource_cookie)
    assert payload.sub == 1
    assert payload.username == "user"
    assert payload.purpose == "resource"


def test_access_token_password_only(monkeypatch):
    """密码登录成功 → 200，access_token 正确，引擎驱动路径。"""
    from app import schemas

    fake_token = schemas.Token(
        access_token="valid.access.token",
        token_type="bearer",
        super_user=False,
        user_id=42,
        user_name="alice",
        avatar=None,
        level=1,
        permissions={},
        wizard=False,
    )

    class FakeService:
        """返回成功登录结果的流程服务桩。"""

        def run_sync(self, submission):
            """验证提交内容并返回成功结果。"""
            assert submission.username == "alice"
            assert submission.password == "secret"
            return {"status": "success", "token": fake_token}

    form_data = SimpleNamespace(username="alice", password="secret")
    request = _build_request()
    response = Response()

    monkeypatch.setattr(login_endpoint, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda result, username, ip: None)

    token = login_endpoint.login_access_token(
        request=request,
        response=response,
        form_data=form_data,
    )

    assert token.access_token == "valid.access.token"
    assert token.user_id == 42
    assert token.user_name == "alice"


def test_access_token_mfa_required_structured_401(monkeypatch):
    """需要 MFA 时 → 401 含 X-MFA-Required 头和 detail['factors_available']。"""

    class FakeService:
        """返回 MFA 必需结果的流程服务桩。"""

        def run_sync(self, submission):
            """返回 MFA 必需结果。"""
            return {
                "status": "mfa_required",
                "flow_token": "tok-abc",
                "factors_available": ["totp", "sms"],
            }

    form_data = SimpleNamespace(username="bob", password="pass")
    request = _build_request()
    response = Response()

    monkeypatch.setattr(login_endpoint, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda result, username, ip: None)

    with pytest.raises(HTTPException) as exc_info:
        login_endpoint.login_access_token(
            request=request,
            response=response,
            form_data=form_data,
        )

    exc = exc_info.value
    assert exc.status_code == 401
    assert exc.headers.get("X-MFA-Required") == "true"
    assert isinstance(exc.detail, dict)
    assert exc.detail["status"] == "mfa_required"
    assert "totp" in exc.detail["factors_available"]
    assert "sms" in exc.detail["factors_available"]


def test_redact_reason_not_leaked(monkeypatch):
    """认证失败时，原始内部错误（如 LDAP 地址）不出现在客户端响应中。"""

    class FakeService:
        """返回含内部敏感错误信息的失败结果的流程服务桩。"""

        def run_sync(self, submission):
            """返回含内部错误的失败结果。"""
            return {
                "status": "failure",
                "error": "LDAP bind 10.0.0.1 refused: invalid credentials",
            }

    form_data = SimpleNamespace(username="eve", password="wrong")
    request = _build_request()
    response = Response()

    monkeypatch.setattr(login_endpoint, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda result, username, ip: None)

    with pytest.raises(HTTPException) as exc_info:
        login_endpoint.login_access_token(
            request=request,
            response=response,
            form_data=form_data,
        )

    exc = exc_info.value
    assert exc.status_code == 401
    detail_str = str(exc.detail)
    assert "LDAP" not in detail_str
    assert "10.0.0.1" not in detail_str
    assert "bind" not in detail_str.lower() or "bind" not in detail_str


def test_plugin_static_file_requires_resource_token_by_default(monkeypatch):
    """普通插件静态资源必须校验资源令牌。"""
    calls = []

    class FakePluginManager:
        """返回空认证提供方的插件管理器桩。"""

        def get_plugin_auth_providers(self):
            """返回插件认证入口列表。"""
            return []

    monkeypatch.setattr(plugin_endpoint, "PluginManager", FakePluginManager)
    monkeypatch.setattr(plugin_endpoint, "verify_resource_token", lambda token: calls.append(token))

    plugin_endpoint._verify_plugin_static_file_access(
        plugin_id="DemoPlugin",
        filepath="dist/remoteEntry.js",
        resource_token="resource-token",
    )

    assert calls == ["resource-token"]


def test_plugin_auth_remote_files_allow_anonymous_bootstrap(monkeypatch):
    """插件登录认证远程组件需要允许登录前匿名加载。"""
    calls = []

    class FakePluginManager:
        """返回认证插件 remote 信息的插件管理器桩。"""

        def get_plugin_auth_providers(self):
            """返回插件认证入口列表。"""
            return [
                {
                    "remote": {
                        "id": "AuthPlugin",
                        "url": "/plugin/file/AuthPlugin/dist/remoteEntry.js",
                    }
                }
            ]

    monkeypatch.setattr(plugin_endpoint, "PluginManager", FakePluginManager)
    monkeypatch.setattr(plugin_endpoint, "verify_resource_token", lambda token: calls.append(token))

    plugin_endpoint._verify_plugin_static_file_access(
        plugin_id="AuthPlugin",
        filepath="dist/remoteEntry.js",
    )
    plugin_endpoint._verify_plugin_static_file_access(
        plugin_id="AuthPlugin",
        filepath="dist/assets/chunk.js",
    )
    plugin_endpoint._verify_plugin_static_file_access(
        plugin_id="authplugin",
        filepath="dist/assets/chunk.js",
    )

    assert calls == []


# ----------------------------- rate limiting 429 -----------------------------

@pytest.fixture()
def reset_login_rate_limiter():
    """Ensure the login rate limiter starts clean before and after this test."""
    from app.api.endpoints import login as login_module
    limiter = getattr(login_module, "_auth_rate_limiter", None)
    if limiter is not None:
        limiter.clear()
    yield
    if limiter is not None:
        limiter.clear()


def test_rate_limit_returns_429(monkeypatch, reset_login_rate_limiter):
    """Hammering /access-token from same ip+username beyond limit → HTTP 429."""
    from app.api.endpoints import login as login_module
    from app.utils.limit import KeyedWindowRateLimiter

    # Use a tight 2-attempt limiter so we hit the ceiling quickly
    tight_limiter = KeyedWindowRateLimiter(max_calls=2, window_seconds=60)
    monkeypatch.setattr(login_module, "_auth_rate_limiter", tight_limiter)

    class FakeService:
        def run_sync(self, submission):
            return {"status": "failure", "error": "invalid_credentials"}

    monkeypatch.setattr(login_module, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(login_module, "emit_auth_event", lambda *a, **kw: None)

    form_data = SimpleNamespace(username="bruteuser", password="badpass")
    request = _build_request()
    response = Response()

    # First 2 calls: under limit → 401 (wrong credentials)
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            login_module.login_access_token(request=request, response=response, form_data=form_data)
        assert exc.value.status_code == 401

    # 3rd call: over limit → 429
    with pytest.raises(HTTPException) as exc:
        login_module.login_access_token(request=request, response=response, form_data=form_data)
    assert exc.value.status_code == 429
    assert "频繁" in exc.value.detail


# ----------------------------- try_record atomicity --------------------------

def test_try_record_capacity_invariant():
    """Single-thread invariant: after max_calls successful try_record, next returns (False, ...)."""
    from app.utils.limit import WindowRateLimiter

    limiter = WindowRateLimiter(max_calls=3, window_seconds=60)

    for i in range(3):
        ok, msg = limiter.try_record()
        assert ok is True, f"call {i+1} should be allowed"
        assert msg == ""

    ok, msg = limiter.try_record()
    assert ok is False
    assert "限流" in msg
    assert "秒" in msg


# ----------------------------- advance 429 -----------------------------------

@pytest.fixture()
def reset_advance_rate_limiter():
    """Ensure the advance rate limiter starts clean before and after this test."""
    from app.api.endpoints import auth as auth_module
    limiter = getattr(auth_module, "_auth_advance_rate_limiter", None)
    if limiter is not None:
        limiter.clear()
    yield
    if limiter is not None:
        limiter.clear()


def test_advance_rate_limit_returns_429(monkeypatch, reset_advance_rate_limiter):
    """Hammering /auth/flow/advance from same ip+username beyond limit → HTTP 429."""
    from app.api.endpoints import auth as auth_module
    from app.utils.limit import KeyedWindowRateLimiter

    tight_limiter = KeyedWindowRateLimiter(max_calls=2, window_seconds=60)
    monkeypatch.setattr(auth_module, "_auth_advance_rate_limiter", tight_limiter)

    class FakeService:
        def advance(self, flow_token, body):
            return {"status": "failure", "error": "invalid_code"}

    monkeypatch.setattr(auth_module, "_build_flow_service", lambda: FakeService())
    monkeypatch.setattr(auth_module, "emit_auth_event", lambda *a, **kw: None)

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/flow/advance",
            "headers": [(b"host", b"testserver")],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 123),
        }
    )

    from types import SimpleNamespace
    body = SimpleNamespace(username="bruteuser", flow_token="tok-x", factor_id=None, answer=None)

    # First 2 calls: under limit → 401 (wrong credentials)
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            auth_module.flow_advance(body=body, request=request)
        assert exc.value.status_code == 401

    # 3rd call: over limit → 429
    with pytest.raises(HTTPException) as exc:
        auth_module.flow_advance(body=body, request=request)
    assert exc.value.status_code == 429
    assert "频繁" in exc.value.detail


def test_upload_avatar_rejects_other_user_for_non_superuser():
    """普通用户不能通过 user_id 参数修改其他用户头像。"""
    current_user = SimpleNamespace(id=1, is_superuser=False)
    upload_file = SimpleNamespace(file=io.BytesIO(b"avatar"), filename="avatar.png")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            user_endpoint.upload_avatar(
                user_id=2,
                db=object(),
                file=upload_file,
                current_user=current_user,
            )
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "用户权限不足"


# ============================= I1: SSO 步 opt-in，密码失败不误转挑战 =============================


class _StubRedirectProvider:
    """最小 SSO 重定向提供方：注册即被 _build_flow_service 桥接为 RedirectStep。"""

    provider_id = "stubsso"
    provider_name = "Stub SSO"
    provider_icon = "mdi-login"
    priority = 100
    enabled = True
    auto_create = True
    success_redirect = "/"

    def authorize_url(self, state, redirect_uri):
        return f"https://idp.example/auth?state={state}"

    def fetch_identity(self, code, redirect_uri):
        return SimpleNamespace(subject="stub-1", username="stubuser", avatar=None)


@pytest.fixture()
def registered_stub_sso():
    """注册 stub SSO 提供方到 redirect 注册表，用例退出后卸载（owner 隔离）。"""
    from app.core.auth import redirect as sso

    provider = _StubRedirectProvider()
    sso.register_auth_provider(provider, owner="i1test")
    try:
        yield provider
    finally:
        sso.unregister_auth_providers("i1test")


@pytest.fixture()
def event_recorder(monkeypatch):
    """捕获 emit_auth_event 经 eventmanager 发出的观测事件（etype 列表）。"""
    from app.api.endpoints import auth as auth_module

    events = []

    def _record(*, etype=None, data=None):
        events.append(etype)
        return SimpleNamespace(event_data=None)

    monkeypatch.setattr(auth_module.eventmanager, "send_event", _record)
    return events


def test_wrong_password_with_sso_provider_fails_not_challenge(
    monkeypatch, registered_stub_sso, event_recorder, reset_login_rate_limiter
):
    """注册了 SSO 重定向提供方时，密码错误仍应 401 '用户名或密码错误'，绝不误转 SSO 跳转挑战。

    回归 I1：RedirectStep 现为 opt-in（仅 requested_step_id 命中才参与）；密码 grant 未选 flow →
    RedirectStep 不 applies_to → 密码失败如实收口为 AuthFailed，而非 MfaChallengeRequired/302。
    """
    from app.api.endpoints import auth as auth_module
    from app.service.auth import flow_steps
    from app.schemas.types import ChainEventType

    # 本地密码校验失败（任何用户名/口令都不通过）
    monkeypatch.setattr(flow_steps.PasswordStep, "_default_authenticate",
                        staticmethod(lambda u, p: None))

    form_data = SimpleNamespace(username="eve", password="wrong")
    request = _build_request()
    response = Response()

    with pytest.raises(HTTPException) as exc_info:
        login_endpoint.login_access_token(request=request, response=response, form_data=form_data)

    exc = exc_info.value
    assert exc.status_code == 401
    assert exc.detail == "用户名或密码错误"          # 非 MFA/challenge 结构体
    assert (exc.headers or {}).get("X-MFA-Required") is None
    # 事件：AuthFailed 而非 MfaChallengeRequired（暴力破解可见）
    assert ChainEventType.AuthFailed in event_recorder
    assert ChainEventType.MfaChallengeRequired not in event_recorder


def test_correct_password_logs_in_with_sso_provider_present(
    monkeypatch, registered_stub_sso, reset_login_rate_limiter
):
    """SSO 重定向提供方在场时，正确密码仍正常登录成功（opt-in 不影响密码主路径）。"""
    from app import schemas
    from app.api.endpoints import auth as auth_module
    from app.service.auth import flow_steps

    user = SimpleNamespace(id=99, name="bob", is_active=True, is_superuser=False,
                           avatar=None, permissions={})
    fake_token = schemas.Token(access_token="tok", token_type="bearer", super_user=False,
                               user_id=99, user_name="bob", avatar=None, level=1,
                               permissions={}, wizard=False)

    monkeypatch.setattr(flow_steps.PasswordStep, "_default_authenticate",
                        staticmethod(lambda u, p: user if (u == "bob" and p == "right") else None))
    # 隔离 DB：装配桥的内建因子与用户加载、Token 铸造改为内存桩
    monkeypatch.setattr(auth_module, "_builtin_factor_steps", lambda u: [])
    monkeypatch.setattr(auth_module, "User",
                        type("FakeUser", (), {"get": staticmethod(lambda db=None, rid=None, **kw: user)}))
    monkeypatch.setattr(auth_module, "build_token_response", lambda u: fake_token)
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda *a, **kw: None)

    form_data = SimpleNamespace(username="bob", password="right")
    request = _build_request()
    response = Response()

    token = login_endpoint.login_access_token(request=request, response=response, form_data=form_data)
    assert token.user_id == 99
    assert token.access_token == "tok"


# ============================= I2: AuxiliaryCredentialStep 恢复媒体服务器辅助认证 ===============


def test_auxiliary_step_present_only_when_enabled(monkeypatch):
    """AUXILIARY_AUTH_ENABLE → 凭证步含 'auxiliary' 且受信；关闭则缺席。"""
    from app.api.endpoints import auth as auth_module
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUXILIARY_AUTH_ENABLE", True)
    svc_on = auth_module._build_flow_service()
    ids_on = [s.step_id for s in svc_on._credential_steps]
    assert "auxiliary" in ids_on
    assert "auxiliary" in svc_on._trusted_step_ids   # 受信，引擎方接受其 user_id

    monkeypatch.setattr(settings, "AUXILIARY_AUTH_ENABLE", False)
    svc_off = auth_module._build_flow_service()
    ids_off = [s.step_id for s in svc_off._credential_steps]
    assert "auxiliary" not in ids_off


def test_auxiliary_step_authenticates_non_local_user(monkeypatch):
    """非本地用户：密码步失败 → 辅助步经媒体服务器模块认证成功 → 登录成功。"""
    from app import schemas
    from app.api.endpoints import auth as auth_module
    from app.core.config import settings
    from app.service.auth import flow_steps
    from app.chain.user import UserChain

    monkeypatch.setattr(settings, "AUXILIARY_AUTH_ENABLE", True)

    user = SimpleNamespace(id=77, name="plexuser", is_active=True, is_superuser=False,
                           avatar=None, permissions={})
    fake_token = schemas.Token(access_token="aux-tok", token_type="bearer", super_user=False,
                               user_id=77, user_name="plexuser", avatar=None, level=1,
                               permissions={}, wizard=False)

    # 本地密码失败（用户非本地）
    monkeypatch.setattr(flow_steps.PasswordStep, "_default_authenticate",
                        staticmethod(lambda u, p: None))
    # 媒体服务器辅助认证成功（桩 auxiliary_authenticate）
    monkeypatch.setattr(UserChain, "auxiliary_authenticate",
                        lambda self, credentials: (True, user))
    monkeypatch.setattr(auth_module, "_builtin_factor_steps", lambda u: [])
    monkeypatch.setattr(auth_module, "User",
                        type("FakeUser", (), {"get": staticmethod(lambda db=None, rid=None, **kw: user)}))
    monkeypatch.setattr(auth_module, "build_token_response", lambda u: fake_token)

    svc = auth_module._build_flow_service()
    out = svc.run_sync(SimpleNamespace(username="plexuser", password="serverpw",
                                       grant_type="password", code=None, mfa_code=None))
    assert out["status"] == "success"
    assert out["token"].user_id == 77


def test_auxiliary_step_user_id_dropped_when_untrusted(monkeypatch):
    """owner-routing 仍生效：辅助步若不在受信集，其直接携带的 user_id 被引擎护栏丢弃。"""
    from app.core.auth.flow import AuthContext
    from app.service.auth.flow_engine import AuthFlow
    from app.core.auth.flow import AnyOf, StepRef
    from app.service.auth.flow_steps import AuxiliaryCredentialStep
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUXILIARY_AUTH_ENABLE", True)
    user = SimpleNamespace(id=5, is_active=True)
    step = AuxiliaryCredentialStep(authenticate=lambda creds: (True, user))
    # 配 resolver 但 trusted 为空 → 非受信步直接给 user_id 被护栏拒绝
    flow = AuthFlow({"auxiliary": step}, AnyOf([StepRef("auxiliary")]),
                    identity_resolver=lambda a: None, trusted_step_ids=frozenset())
    ctx, result = flow.advance(AuthContext(flow_id="f1", username="x"),
                               SimpleNamespace(username="x", password="pw", grant_type="password",
                                               code=None))
    assert result.kind == "failure"            # user_id 被丢弃 → 无身份落地
    assert ctx.resolved_user_id is None


# ============================= M3: flow 成功写入资源 Cookie ===================================


def test_flow_begin_sets_resource_token_cookie(monkeypatch):
    """/auth/flow/begin 成功（带 Token）应写入资源 Cookie，与 /access-token 行为一致。"""
    from app import schemas
    from app.api.endpoints import auth as auth_module

    fake_token = schemas.Token(access_token="f.jwt", token_type="bearer", super_user=False,
                               user_id=7, user_name="kit", avatar="", level=1,
                               permissions={"discovery": True}, wizard=False)

    class FakeService:
        def begin(self, body):
            return {"status": "success", "token": fake_token}

    monkeypatch.setattr(auth_module, "_build_flow_service", lambda request=None: FakeService())
    monkeypatch.setattr(auth_module, "emit_auth_event", lambda *a, **kw: None)

    request = _build_request()
    response = Response()
    result = auth_module.flow_begin(body=schemas.FlowBeginRequest(username="kit"),
                                    request=request, response=response)

    assert result["status"] == "success"
    assert "set-cookie" in response.headers
    cookie = response.headers["set-cookie"].split("=", 1)[1].split(";", 1)[0]
    payload = verify_resource_token(cookie)
    assert payload.sub == 7
    assert payload.username == "kit"
    assert payload.purpose == "resource"


def test_flow_advance_sets_resource_token_cookie(monkeypatch, reset_advance_rate_limiter):
    """/auth/flow/advance 成功（带 Token）同样写入资源 Cookie。"""
    from app import schemas
    from app.api.endpoints import auth as auth_module

    fake_token = schemas.Token(access_token="f2.jwt", token_type="bearer", super_user=False,
                               user_id=8, user_name="ada", avatar="", level=1,
                               permissions={}, wizard=False)

    class FakeService:
        def advance(self, flow_token, body):
            return {"status": "success", "token": fake_token}

    monkeypatch.setattr(auth_module, "_build_flow_service", lambda request=None: FakeService())
    monkeypatch.setattr(auth_module, "emit_auth_event", lambda *a, **kw: None)

    request = Request({
        "type": "http", "method": "POST", "path": "/api/v1/auth/flow/advance",
        "headers": [(b"host", b"testserver")], "scheme": "http",
        "server": ("testserver", 80), "client": ("testclient", 123),
    })
    response = Response()
    body = schemas.FlowAdvanceRequest(flow_token="tok", step_id="otp", code="246")
    result = auth_module.flow_advance(body=body, request=request, response=response)

    assert result["status"] == "success"
    assert "set-cookie" in response.headers
    cookie = response.headers["set-cookie"].split("=", 1)[1].split(";", 1)[0]
    payload = verify_resource_token(cookie)
    assert payload.sub == 8
    assert payload.purpose == "resource"
