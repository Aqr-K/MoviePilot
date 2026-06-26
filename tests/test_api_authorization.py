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
