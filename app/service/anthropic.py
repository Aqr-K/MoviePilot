"""
Anthropic 兼容端点的纯逻辑（service layer）。

错误响应构造与 x-api-key 鉴权校验。均为确定性的纯函数，不依赖 Chain/agent，
可独立单测。端点 app/api/endpoints/anthropic.py 负责 agent 流式编排与路由。
"""
from typing import Optional

from fastapi.responses import JSONResponse

from app import schemas
from app.core.config import settings
from app.core.security import compare_secret


def anthropic_error_response(
    message: str,
    status_code: int,
    error_type: str = "invalid_request_error",
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=schemas.AnthropicErrorResponse(
            error=schemas.AnthropicErrorDetail(type=error_type, message=message)
        ).model_dump(),
    )


def check_auth(api_key: Optional[str]) -> Optional[JSONResponse]:
    """
    Anthropic 兼容接口以 API_TOKEN 认证受信客户端，认证通过即按管理员级 Agent 集成处理。
    """
    if not compare_secret(api_key, settings.API_TOKEN):
        return anthropic_error_response(
            "invalid x-api-key",
            401,
            error_type="authentication_error",
        )
    return None
