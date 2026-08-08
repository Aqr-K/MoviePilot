"""
S7d 抽取验证：app.service.anthropic 纯逻辑单测（错误响应 / x-api-key 鉴权）。

端点 app/api/endpoints/anthropic.py 经 openai 端点 import app.agent，触发 jieba_next
缺口，在本环境不可导入；抽出到 agent-free 的 service 后可在 venv 直接覆盖。
"""
import json

from app.core.config import settings
from app.service import anthropic as svc


def _body(resp):
    return json.loads(resp.body)


def test_anthropic_error_response_shape():
    resp = svc.anthropic_error_response("bad", 400, error_type="invalid_request_error")
    assert resp.status_code == 400
    body = _body(resp)
    assert body["error"]["type"] == "invalid_request_error"
    assert body["error"]["message"] == "bad"


def test_check_auth_missing_key():
    resp = svc.check_auth(None)
    assert resp is not None
    assert resp.status_code == 401
    assert _body(resp)["error"]["type"] == "authentication_error"


def test_check_auth_wrong_key(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "right", raising=False)
    resp = svc.check_auth("wrong")
    assert resp is not None
    assert resp.status_code == 401


def test_check_auth_valid_returns_none(monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", "right", raising=False)
    assert svc.check_auth("right") is None
