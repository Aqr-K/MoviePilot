from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app import schemas
from app.core import sso
from app.core.auth_bridge import build_token_response, consume_plugin_auth_ticket
from app.core.config import settings
from app.helper.plugin_manager import PluginManager
from app.helper.sso import begin_login, complete_login
from app.log import logger
from app.db.models.passkey import PassKey
from app.db.models.user import User

router = APIRouter()

# SSO 端点前缀（auth.router 挂载于 /api/v1/auth）
_SSO_BASE = "/api/v1/auth/sso"


class AuthExchangeRequest(BaseModel):
    """
    插件认证票据兑换请求。
    """

    ticket: str


def _system_auth_providers() -> list[dict[str, Any]]:
    """
    获取系统内建的匿名登录方式摘要。

    :return: 系统认证提供方列表
    """
    has_passkey = bool(PassKey.list(db=None))
    return [
        {
            "id": "system:passkey",
            "type": "system",
            "method": "passkey",
            "name": "通行密钥",
            "icon": "material-symbols:passkey",
            "enabled": has_passkey,
        }
    ]


def _registered_sso_providers() -> list[dict[str, Any]]:
    """
    由 app.core.sso 注册表（provides_auth_providers）派生登录入口摘要。

    每个注册提供方自动获得 `/auth/sso/{id}/login` 入口（框架统一驱动 OAuth），无需插件再声明端点。

    :return: SSO 认证提供方列表
    """
    items: list[dict[str, Any]] = []
    for provider in sso.all_auth_providers():
        pid = getattr(provider, "provider_id", None)
        if not pid:
            continue
        items.append({
            "id": pid,
            "type": "sso",
            "name": getattr(provider, "provider_name", pid),
            "icon": getattr(provider, "provider_icon", ""),
            "method": "redirect",
            "login_url": f"{_SSO_BASE}/{pid}/login",
            "enabled": bool(getattr(provider, "enabled", True)),
        })
    return items


@router.get("/providers", summary="查询登录认证提供方", response_model=list[dict])
def auth_providers() -> list[dict[str, Any]]:
    """
    查询系统、插件与注册的 SSO 提供方提供的登录认证入口。

    :return: 认证提供方摘要列表
    """
    providers = _system_auth_providers()
    providers.extend(PluginManager().get_plugin_auth_providers())
    providers.extend(_registered_sso_providers())
    return [provider for provider in providers if provider.get("enabled", True)]


@router.post("/exchange", summary="兑换插件认证登录票据", response_model=schemas.Token)
def auth_exchange(body: AuthExchangeRequest) -> schemas.Token:
    """
    将插件认证成功后生成的一次性票据兑换为系统 Token。

    :param body: 票据兑换请求
    :return: 标准登录 Token
    """
    ticket_data = consume_plugin_auth_ticket(body.ticket)
    if not ticket_data:
        raise HTTPException(status_code=401, detail="认证票据无效或已过期")

    user = User.get(db=None, rid=ticket_data.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="用户不存在或已禁用")

    return build_token_response(user)


def _sso_redirect_uri(provider_id: str, request: Request) -> str:
    """构造 OAuth redirect_uri（须与 IdP 注册回调一致）：优先 APP_DOMAIN，否则从请求 Host 推导。"""
    path = f"{_SSO_BASE}/{provider_id}/callback"
    domain_url = settings.MP_DOMAIN(path)
    if domain_url:
        return domain_url
    # 兜底：从请求 Host 推导，依赖反代正确校验 Host 头；生产应配置 APP_DOMAIN
    logger.warning("SSO 未配置 APP_DOMAIN，回退用请求 Host 推导 redirect_uri，存在 Host 头注入风险")
    return f"{str(request.base_url).rstrip('/')}{path}"


def _safe_relative(path: Optional[str]) -> str:
    """约束跳转为站内相对路径，避免票据被 302 到外部域（票据可兑换 Token）。"""
    p = (path or "/").strip()
    if (not p.startswith("/") or p.startswith("//") or "://" in p
            or "\\" in p or any(c < " " for c in p)):
        return "/"
    return p


def _sso_redirect_back(success_redirect: str, ticket: Optional[str] = None,
                       error: Optional[str] = None) -> RedirectResponse:
    """重定向回前端：成功带 ?ticket=（前端再调 /auth/exchange 换 Token），失败带 ?sso_error=。"""
    from urllib.parse import urlencode
    # 保底再过滤一次，确保任何调用方传入的 success_redirect 均为站内相对路径
    success_redirect = _safe_relative(success_redirect)
    base = settings.MP_DOMAIN(success_redirect) or success_redirect
    query = {}
    if ticket:
        query["ticket"] = ticket
    if error:
        query["sso_error"] = error
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}{urlencode(query)}" if query else base
    return RedirectResponse(url=url)


@router.get("/sso/{provider_id}/login", summary="发起 SSO 登录")
def sso_login(provider_id: str, request: Request) -> RedirectResponse:
    """将浏览器重定向到指定 SSO 提供方的 IdP 授权页（框架签发 CSRF state）。"""
    provider = sso.get_auth_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="未知的登录提供方")
    return RedirectResponse(url=begin_login(provider, _sso_redirect_uri(provider_id, request)))


@router.get("/sso/{provider_id}/callback", summary="SSO 登录回调")
def sso_callback(provider_id: str, request: Request, code: str = "", state: str = "") -> RedirectResponse:
    """处理 IdP 回调：框架统一完成 state 校验 / 换身份 / 用户解析建号 / 铸票，再重定向回前端。"""
    provider = sso.get_auth_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="未知的登录提供方")
    success_redirect = _safe_relative(getattr(provider, "success_redirect", "/"))
    auto_create = bool(getattr(provider, "auto_create", False))
    ticket, error = complete_login(provider, code, state,
                                   _sso_redirect_uri(provider_id, request), auto_create=auto_create)
    return _sso_redirect_back(success_redirect, ticket=ticket, error=error)
