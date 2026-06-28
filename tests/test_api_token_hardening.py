"""API_TOKEN 加固回归测试（架构审计 3.A #53）。

覆盖两处加固：
  1) API_TOKEN 首选请求头 X-API-TOKEN（保留 query 向后兼容但优先 header）。
  2) 服务令牌（API_TOKEN）降权：验证后身份 super_user=False，
     且 get_current_active_superuser/_async 真正校验 token_data.super_user。
"""
from types import SimpleNamespace

import asyncio
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app import schemas
from app.core import security
from app.db.user_oper import (
    get_current_active_superuser,
    get_current_active_superuser_async,
)

# 模块内的 "私有" 函数（双下划线前缀，模块级不发生名称改写）
_get_api_token = getattr(security, "__get_api_token")
_create_service_token_payload = getattr(security, "__create_service_token_payload")


def _build_request() -> Request:
    """构造最小测试请求。"""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/system/env",
            "headers": [(b"host", b"testserver")],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 123),
        }
    )


# ----------------------------- 1) token header 优先 -----------------------------

def test_api_token_header_scheme_uses_x_api_token():
    """新增的 API_TOKEN 请求头方案名为 X-API-TOKEN。"""
    assert security.api_token_header.model.name == "X-API-TOKEN"


def test_get_api_token_prefers_header_over_query():
    """__get_api_token 优先返回请求头，缺失时回退查询参数。"""
    assert _get_api_token(token_header="from-header", token_query="from-query") == "from-header"
    assert _get_api_token(token_header="from-header", token_query=None) == "from-header"
    assert _get_api_token(token_header=None, token_query="from-query") == "from-query"
    assert _get_api_token(token_header=None, token_query=None) is None


# ----------------------------- 2) 服务令牌降权 -----------------------------

def test_create_service_token_payload_is_non_superuser(monkeypatch):
    """服务令牌 payload 即使底层用户是超管，也声明 super_user=False。"""
    from app.db import user_oper

    fake_user = SimpleNamespace(id=7, name="admin", is_superuser=True)

    class FakeUserOper:
        """返回超管用户的桩。"""

        def get_by_name(self, _name):
            """返回固定的超管用户。"""
            return fake_user

    monkeypatch.setattr(user_oper, "UserOper", FakeUserOper)
    monkeypatch.setattr(security, "get_auth_level", lambda: 1)

    _create_service_token_payload.cache_clear()
    try:
        payload = _create_service_token_payload()
    finally:
        _create_service_token_payload.cache_clear()

    assert payload.super_user is False
    assert payload.sub == 7
    assert payload.purpose == "authentication"


def test_verify_token_api_token_returns_non_superuser_payload(monkeypatch):
    """verify_token 经 API_TOKEN 鉴权后返回非超管 payload，且不铸造超管 payload。"""
    service_payload = schemas.TokenPayload(
        sub=7, username="admin", super_user=False, level=1, purpose="authentication"
    )
    monkeypatch.setattr(security.settings, "API_TOKEN", "secret-token")
    monkeypatch.setattr(security, "__create_service_token_payload", lambda: service_payload)

    result = security.verify_token(
        _build_request(),
        Response(),
        jwt_token=None,
        api_key=None,
        api_token="secret-token",
    )

    assert result.super_user is False
    assert result.sub == 7


def test_verify_token_api_key_returns_non_superuser_payload(monkeypatch):
    """#53 旁路回归：经 ?apikey=<API_TOKEN>（与 token 同一密钥）鉴权也必须返回非超管 payload，
    不得铸造超管身份——否则攻击者改用 apikey 参数名即可绕过 api_token 分支降权。"""
    service_payload = schemas.TokenPayload(
        sub=7, username="admin", super_user=False, level=1, purpose="authentication"
    )
    monkeypatch.setattr(security.settings, "API_TOKEN", "secret-token")
    monkeypatch.setattr(security, "__create_service_token_payload", lambda: service_payload)

    result = security.verify_token(
        _build_request(),
        Response(),
        jwt_token=None,
        api_key="secret-token",
        api_token=None,
    )

    assert result.super_user is False
    assert result.sub == 7


# ------------------- 2b) 超管守卫真正校验 token_data.super_user -------------------

def test_get_current_active_superuser_rejects_non_superuser_token():
    """即使 DB 用户是超管，令牌声明 super_user=False 也必须被拒绝（401/400）。"""
    db_superuser = SimpleNamespace(id=7, is_superuser=True)
    service_payload = schemas.TokenPayload(
        sub=7, username="admin", super_user=False, level=1, purpose="authentication"
    )

    with pytest.raises(HTTPException) as exc:
        get_current_active_superuser(current_user=db_superuser, token_data=service_payload)
    assert exc.value.status_code == 400
    assert exc.value.detail == "用户权限不足"


def test_get_current_active_superuser_allows_real_superuser_token():
    """令牌声明 super_user=True 且 DB 用户为超管时放行。"""
    db_superuser = SimpleNamespace(id=7, is_superuser=True)
    su_payload = schemas.TokenPayload(
        sub=7, username="admin", super_user=True, level=1, purpose="authentication"
    )
    assert get_current_active_superuser(current_user=db_superuser, token_data=su_payload) is db_superuser


def test_get_current_active_superuser_async_rejects_non_superuser_token():
    """异步超管守卫同样校验 token_data.super_user。"""
    db_superuser = SimpleNamespace(id=7, is_superuser=True)
    service_payload = schemas.TokenPayload(
        sub=7, username="admin", super_user=False, level=1, purpose="authentication"
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            get_current_active_superuser_async(current_user=db_superuser, token_data=service_payload)
        )
    assert exc.value.status_code == 400
