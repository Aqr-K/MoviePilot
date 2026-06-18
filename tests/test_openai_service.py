"""
S7d 抽取验证：app.service.openai 纯逻辑单测（SSE 负载 / 错误响应 / Bearer 鉴权）。

端点 app/api/endpoints/openai.py 因 import app.agent 触发 jieba_next 缺口，在本环境
不可导入；抽出到 agent-free 的 service 后这些（含安全相关的鉴权）逻辑可在 venv 直接覆盖。
"""
import json

from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import settings
from app.service import openai as svc


def _body(resp):
    return json.loads(resp.body)


def test_sse_payload_format_and_unicode():
    out = svc.sse_payload({"a": "中文"})
    assert out.startswith("data: ")
    assert out.endswith("\n\n")
    assert "中文" in out
    assert json.loads(out[len("data: "):].strip()) == {"a": "中文"}


def test_error_response_shape():
    resp = svc.error_response("boom", 400, error_type="invalid_request_error", code="x")
    assert resp.status_code == 400
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    body = _body(resp)
    assert body["error"]["message"] == "boom"
    assert body["error"]["type"] == "invalid_request_error"
    assert body["error"]["code"] == "x"


def test_check_auth_missing_credentials():
    resp = svc.check_auth(None)
    assert resp is not None
    assert resp.status_code == 401
    assert _body(resp)["error"]["code"] == "invalid_api_key"


def test_check_auth_wrong_scheme():
    creds = HTTPAuthorizationCredentials(scheme="Basic", credentials="whatever")
    resp = svc.check_auth(creds)
    assert resp is not None
    assert resp.status_code == 401


def test_check_auth_wrong_token(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "right-token", raising=False)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong-token")
    resp = svc.check_auth(creds)
    assert resp is not None
    assert resp.status_code == 401


def test_check_auth_valid_returns_none(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "right-token", raising=False)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="right-token")
    assert svc.check_auth(creds) is None
