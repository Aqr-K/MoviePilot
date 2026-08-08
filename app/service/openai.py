"""
OpenAI 兼容端点的纯逻辑（service layer）。

SSE 负载格式化、错误响应构造、Bearer 鉴权校验。均为确定性的纯函数，
不依赖 Chain/agent，可独立单测。端点 app/api/endpoints/openai.py 负责
agent 流式编排与路由。
"""
import json
from typing import Optional

from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from app import schemas
from app.core.config import settings
from app.core.security import compare_secret


def sse_payload(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def error_response(
    message: str,
    status_code: int,
    error_type: str = "invalid_request_error",
    code: Optional[str] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=schemas.OpenAIErrorResponse(
            error=schemas.OpenAIErrorDetail(
                message=message,
                type=error_type,
                code=code,
            )
        ).model_dump(),
        headers={"WWW-Authenticate": "Bearer"},
    )


def check_auth(
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[JSONResponse]:
    """
    OpenAI 兼容接口以 API_TOKEN 认证受信客户端，认证通过即按管理员级 Agent 集成处理。
    """
    if not credentials or credentials.scheme.lower() != "bearer":
        return error_response(
            "Invalid bearer token.",
            401,
            error_type="authentication_error",
            code="invalid_api_key",
        )
    if not compare_secret(credentials.credentials, settings.API_TOKEN):
        return error_response(
            "Invalid bearer token.",
            401,
            error_type="authentication_error",
            code="invalid_api_key",
        )
    return None
