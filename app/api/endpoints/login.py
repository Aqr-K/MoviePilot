import types as _types
from typing import Any, List, Annotated

from fastapi import Depends, Form, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from app import schemas
from app.api.response import RAW_RESPONSE_OPENAPI_KEY, ResponseAPIRouter
from app.core import security
from app.helper.image import WallpaperHelper
from app.core.auth_rate_limit import auth_rate_limiter
from app.schemas import RateLimitExceededException

# Re-exported at module level so tests can monkeypatch on login_endpoint directly.
from app.api.endpoints.auth import _build_flow_service, emit_auth_event

router = ResponseAPIRouter()

# 共享认证限流器（与 /auth/flow 同一桶，避免同 ip:username 暴破预算翻倍）；
# 保留模块级别名供端点代码引用与测试 monkeypatch。
_auth_rate_limiter = auth_rate_limiter


@router.post(
    "/access-token",
    summary="获取token",
    response_model=schemas.Token,
    responses={
        401: {
            "model": schemas.Response[schemas.MfaChallenge],
            "description": "需要二次验证或认证失败",
        }
    },
    openapi_extra={RAW_RESPONSE_OPENAPI_KEY: True},
)
def login_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    otp_password: Annotated[str | None, Form()] = None,
) -> Any:
    """
    获取认证Token（引擎驱动：通过 FlowService.run_sync 完成凭证验证与条件 MFA）。
    """
    client_ip = request.client.host if request.client else "unknown"
    rl_key = f"{client_ip}:{form_data.username}"
    try:
        _auth_rate_limiter.check(rl_key)
    except RateLimitExceededException:
        raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")

    submission = _types.SimpleNamespace(
        username=form_data.username,
        password=form_data.password,
        grant_type=getattr(form_data, "grant_type", "password") or "password",
        code=otp_password,
        mfa_code=otp_password,
    )
    service = _build_flow_service()
    result = service.run_sync(submission)

    client_ip = request.client.host if request.client else None
    emit_auth_event(result, form_data.username, client_ip)

    if result.get("status") == "success":
        token = result["token"]
        # 铸资源 Cookie（浏览器侧插件静态文件鉴权所需），与 /auth/flow 路径保持一致行为
        security.set_or_refresh_resource_token_cookie(
            request,
            response,
            schemas.TokenPayload(
                sub=token.user_id,
                username=token.user_name,
                super_user=token.super_user,
                level=token.level,
                purpose="authentication",
            ),
        )
        return token

    if result.get("status") in ("mfa_required", "challenge"):
        raise HTTPException(
            status_code=401,
            detail={
                "message": "需要双重验证，请提供验证码或使用通行密钥",
                "status": "mfa_required",
                "factors_available": result.get("factors_available") or [],
            },
            headers={"X-MFA-Required": "true"},
        )

    raise HTTPException(status_code=401, detail="用户名或密码错误")


@router.get(
    "/wallpaper",
    summary="登录页面电影海报",
    response_model=schemas.Response[str],
)
def wallpaper() -> Any:
    """
    获取登录页面电影海报
    """
    url = WallpaperHelper().get_wallpaper()
    if url:
        return schemas.Response(success=True, data=url)
    return schemas.Response(success=False)


@router.get("/wallpapers", summary="登录页面电影海报列表", response_model=List[str])
def wallpapers() -> Any:
    """
    获取登录页面电影海报
    """
    return WallpaperHelper().get_wallpapers()
