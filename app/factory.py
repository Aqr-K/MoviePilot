from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.startup.lifecycle import lifespan


def _cors_allow_credentials(origins: list) -> bool:
    """CORS 凭证与通配源 ``*`` 不可共存（浏览器拒绝 ``*``+credentials，服务端声明该组合属误配）：
    允许源含 ``*`` 时禁用凭证，仅当配置了具体源时才放行带凭证的跨域请求。"""
    return "*" not in origins


def create_app() -> FastAPI:
    """
    创建并配置 FastAPI 应用实例。
    """
    _app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan
    )

    # 配置 CORS 中间件
    _app.add_middleware(
        CORSMiddleware,  # noqa
        allow_origins=settings.ALLOWED_HOSTS,
        allow_credentials=_cors_allow_credentials(settings.ALLOWED_HOSTS),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return _app


# 创建 FastAPI 应用实例
app = create_app()
