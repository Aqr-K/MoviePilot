"""
LLM 端点的纯逻辑（service layer）。

错误信息脱敏：从 LLM 测试调用的异常文本中抹去 API 密钥 / Bearer 令牌，
避免敏感凭据经由错误响应回显。纯函数，不依赖 Chain/DB/agent，可独立单测。
"""
import re
from typing import Optional


def sanitize_llm_test_error(message: str, api_key: Optional[str] = None) -> str:
    """
    清理错误信息中的敏感字段，避免回显密钥。
    """
    if not message:
        return "LLM 没有返回任何内容"

    sanitized = message
    if api_key:
        sanitized = sanitized.replace(api_key, "***")
    sanitized = re.sub(
        r"(?i)(api[_-]?key\s*[:=]\s*)([^\s,;]+)",
        r"\1***",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)authorization\s*:\s*bearer\s+[^\s,;]+",
        "Authorization: ***",
        sanitized,
    )

    normalized_message = sanitized.lower().replace("_", "").replace(" ", "")
    if "str" in normalized_message and "modeldump" in normalized_message:
        return (
            "服务返回内容不是兼容的模型响应，"
            "请检查基础地址是否填写为 API Base URL，不要填写网页地址或完整的 "
            "chat/completions 路径"
        )
    return sanitized
