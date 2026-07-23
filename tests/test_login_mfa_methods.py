"""登录接口的 MFA 方法暴露边界。

v3 的密码登录由 ``app/service/auth`` 引擎驱动：凭证校验通过后才进入 MFA 步骤，
可用因子经 ``factors_available`` 结构化返回；密码未通过时只返回通用失败信息。
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app.api.endpoints import login as login_endpoint
from app.service.auth.builtin_factors import OtpFactor, PasskeyFactor


def _request() -> Request:
    """构造登录接口所需的最小请求。"""
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


def _form() -> SimpleNamespace:
    """构造密码登录表单契约。"""
    return SimpleNamespace(username="user", password="password", grant_type="password")


def _service(result: dict) -> SimpleNamespace:
    """构造返回固定结果的认证流服务。"""
    return SimpleNamespace(run_sync=lambda submission: result)


def test_otp_factor_is_offered_when_enrolled():
    """账号启用 OTP 时应作为可用二次验证方式给出挑战提示。"""
    user = SimpleNamespace(id=1, name="user", is_otp=True, otp_secret="")
    factor = OtpFactor(is_enrolled=lambda _u: True, verify=lambda _u, _c: False)

    hint = factor.challenge_hint(user)

    assert hint is not None
    assert hint.factor_id == "otp"


def test_factor_not_offered_when_not_enrolled():
    """未注册的因子不得出现在可用方式中，避免泄露账号安全配置。"""
    user = SimpleNamespace(id=1, name="user", is_otp=False, otp_secret="")

    assert OtpFactor(is_enrolled=lambda _u: False,
                     verify=lambda _u, _c: False).challenge_hint(user) is None
    assert PasskeyFactor(is_enrolled=lambda _u: False).challenge_hint(user) is None


def test_login_mfa_response_contains_methods_after_password_verification(monkeypatch):
    """MFA 响应应保持旧标记并补充结构化方法列表。"""
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda *a, **kw: None)
    monkeypatch.setattr(
        login_endpoint,
        "_build_flow_service",
        lambda: _service({"status": "mfa_required", "factors_available": ["otp"]}),
    )

    with pytest.raises(HTTPException) as exc_info:
        login_endpoint.login_access_token(
            request=_request(),
            response=Response(),
            form_data=_form(),
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers["X-MFA-Required"] == "true"
    assert exc_info.value.detail["status"] == "mfa_required"
    assert exc_info.value.detail["factors_available"] == ["otp"]


def test_login_invalid_password_does_not_expose_mfa_methods(monkeypatch):
    """密码未通过时不得返回账号的 MFA 能力。"""
    monkeypatch.setattr(login_endpoint, "emit_auth_event", lambda *a, **kw: None)
    monkeypatch.setattr(
        login_endpoint,
        "_build_flow_service",
        lambda: _service({"status": "failure"}),
    )

    with pytest.raises(HTTPException) as exc_info:
        login_endpoint.login_access_token(
            request=_request(),
            response=Response(),
            form_data=_form(),
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "用户名或密码错误"
    assert "X-MFA-Required" not in (exc_info.value.headers or {})
