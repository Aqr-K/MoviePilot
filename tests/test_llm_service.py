"""
S7c 抽取验证：app.service.llm.sanitize_llm_test_error 脱敏逻辑单测。

该函数为安全相关（防止 API 密钥/Bearer 令牌经错误响应回显），原埋在
app/api/endpoints/llm.py，其端点级测试 test_llm_endpoint_error_messages.py 在本
环境因 jieba_next 缺口收集失败；抽出到不依赖 agent 的 service 后可在 venv 直接覆盖。
"""
from app.service import llm


def test_empty_message_returns_placeholder():
    assert llm.sanitize_llm_test_error("") == "LLM 没有返回任何内容"
    assert llm.sanitize_llm_test_error(None) == "LLM 没有返回任何内容"


def test_redacts_literal_api_key():
    out = llm.sanitize_llm_test_error("请求失败 key=sk-abc123 无效", api_key="sk-abc123")
    assert "sk-abc123" not in out
    assert "***" in out


def test_redacts_api_key_assignment_pattern():
    out = llm.sanitize_llm_test_error("error: api_key=supersecret found")
    assert "supersecret" not in out
    assert "api_key=***" in out


def test_redacts_api_key_dash_colon_pattern():
    out = llm.sanitize_llm_test_error("API-KEY: topsecret")
    assert "topsecret" not in out
    assert "***" in out


def test_redacts_authorization_bearer():
    out = llm.sanitize_llm_test_error("Authorization: Bearer tok_987654")
    assert "tok_987654" not in out
    assert "Authorization: ***" in out


def test_model_dump_heuristic_returns_friendly_message():
    out = llm.sanitize_llm_test_error("'str' object has no attribute 'model_dump'")
    assert "API Base URL" in out
    assert "model_dump" not in out


def test_plain_message_unchanged():
    msg = "连接超时，请稍后重试"
    assert llm.sanitize_llm_test_error(msg) == msg


def test_api_key_none_does_not_crash():
    assert llm.sanitize_llm_test_error("just a message", api_key=None) == "just a message"
