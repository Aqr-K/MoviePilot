import types
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app import schemas
from app.core.auth import redirect as sso
from app.core.auth_bridge import build_token_response, consume_plugin_auth_ticket
from app.core.config import settings
from app.core.event import eventmanager
from app.helper.plugin_manager import PluginManager
from app.helper.sso import begin_login
from app.service.auth.sso_flow import sso_callback_query
from app.log import logger
from app.schemas.event import AuthObservationEventData, MfaChallengeEventData
from app.schemas.types import ChainEventType
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_service import redact_reason
from app.db.models.passkey import PassKey
from app.db.models.user import User

router = APIRouter()

# SSO 端点前缀（auth.router 挂载于 /api/v1/auth）
_SSO_BASE = "/api/v1/auth/sso"

# 多步登录流程状态存储（进程级，跨请求承载未完成的流程；重启失效=重新登录，可接受）
_FLOW_STORE = FlowStore()


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
    由 app.core.auth.redirect 注册表（provides_auth_providers）派生登录入口摘要。

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


class FlowBeginRequest(BaseModel):
    """开始多步登录流程的请求（通常携带用户名/口令；也可用于纯枚举步骤）。"""

    username: Optional[str] = None
    password: Optional[str] = None
    grant_type: str = "password"


class FlowAdvanceRequest(BaseModel):
    """推进多步登录流程的请求（提交因子码 / 挑战应答 / 后补凭证）。"""

    flow_token: str
    step_id: Optional[str] = None
    code: Optional[str] = None
    response: Optional[dict] = None
    username: Optional[str] = None
    password: Optional[str] = None
    grant_type: str = "password"


# 装配桥按 step_kind 切分全局步骤注册表：以下种归入【凭证阶段】（解析用户），其余 "factor" 归第二因子阶段。
_CREDENTIAL_STEP_KINDS = {"credential", "directory", "federated_direct", "redirect"}
# 防内建 id 冒充（Task 9 review #1a）：排除任何声称内建 id 的插件凭证步，杜绝插件以 "password"
# 影子化/继承受信而直接落 user_id 绕过 owner 分流。内建受信步仅由本地 PasswordStep 提供。
BUILTIN_CREDENTIAL_IDS = {"password"}


def _builtin_factor_steps(user) -> list:
    """该用户的 per-user 内建第二因子（OTP/PassKey，经闭包绑定到本 user）包装为 ``FactorStep``。

    与 ``orchestrator.factors_for_user`` 的内建部分同构，但**不含** ``all_mfa_factors()``——插件因子改由
    ``all_auth_steps()`` 的 "factor" 种步骤注入，故此处只构内建，避免与注册表里的插件因子双计。
    内建 OTP/PassKey 天然 per-user（闭包绑定 user.otp_secret/passkey），无法做全局注册表步，故保留内建装配。
    """
    from app.db.models.passkey import PassKey
    from app.service.auth.builtin_factors import build_builtin_factors
    from app.service.auth.flow_steps import FactorStep
    from app.utils.otp import OtpUtils

    builtin = build_builtin_factors(
        is_otp_enrolled=lambda _ref: bool(getattr(user, "is_otp", False)),
        verify_otp=lambda _ref, code: OtpUtils.check(str(user.otp_secret), code),
        has_passkey=lambda _ref: bool(PassKey.get_by_user_id(db=None, user_id=user.id)),
    )
    return [FactorStep(f) for f in builtin]


def _build_flow_service():
    """按全局步骤注册表（``all_auth_steps()``）实时装配多步登录服务（装配桥）。

    - 凭证步 = 本地 ``PasswordStep`` + 注册表中 step_kind ∈ ``_CREDENTIAL_STEP_KINDS`` 的插件步（排除冒充内建 id 者）；
    - 第二因子步 = 该用户的 per-user 内建因子 + 注册表中 step_kind=="factor" 的插件步（applies_to 自行 per-user 过滤）。

    插件步统一经唯一 SPI ``provides_auth_steps()`` 注册（owner=plugin_id）；不再依赖 ``all_credential_providers()``
    与 ``orchestrator.factors_for_user()``。复用 ``build_token_response`` 作为唯一铸 Token 来源。
    """
    from app.core.auth.flow_registry import get_auth_flow
    from app.core.auth.steps import all_auth_steps
    from app.service.auth.flow_service import FlowService
    from app.service.auth.flow_steps import PasswordStep, make_identity_resolver
    from app.service.auth.provisioning import default_deps

    steps = all_auth_steps()
    credential_steps = [PasswordStep()] + [
        s for s in steps
        if getattr(s, "step_kind", None) in _CREDENTIAL_STEP_KINDS
        and getattr(s, "step_id", None) not in BUILTIN_CREDENTIAL_IDS
    ]
    plugin_factor_steps = [s for s in steps if getattr(s, "step_kind", None) == "factor"]

    # 流程形状可插拔：若有插件注册了名为 "default" 的流程规格（如 N-of-M 强 MFA），用其组合策略；
    # 否则沿用默认 AnyOf（任一因子，复现 v2 OR）。注册期 verify_flow_spec_contract 已拒绝"空真"规格，
    # 杜绝插件以 default 规格 vacuous 绕过 MFA。
    default_spec = get_auth_flow("default")
    mfa_requirement = (lambda steps: default_spec.mfa_requirement(steps)) if default_spec else None
    return FlowService(
        flow_store=_FLOW_STORE,
        credential_steps=credential_steps,
        factor_steps_for=lambda user: _builtin_factor_steps(user) + plugin_factor_steps,
        load_user=lambda uid: User.get(db=None, rid=uid),
        issue_token=build_token_response,
        mfa_requirement=mfa_requirement,
        identity_resolver=make_identity_resolver(default_deps()),
        trusted_step_ids=BUILTIN_CREDENTIAL_IDS,
    )


def emit_auth_event(result: dict, username: Optional[str], client_ip: Optional[str]) -> None:
    """流程结果 → 观测事件（fire-and-forget，绝不阻断登录；reason 经脱敏白名单过滤）。

    同时供 /access-token（login.py）与 /auth/flow 端点使用，是唯一事件发射路径。
    """
    try:
        status = result.get("status")
        if status == "success":
            name = (result.get("token") or {})
            uname = getattr(name, "user_name", None) or username
            eventmanager.send_event(
                etype=ChainEventType.AuthSucceeded,
                data=AuthObservationEventData(username=uname or "", success=True, client_ip=client_ip))
        elif status == "failure":
            eventmanager.send_event(
                etype=ChainEventType.AuthFailed,
                data=AuthObservationEventData(username=username or "", success=False,
                                              reason=redact_reason(result.get("error") or "auth_failed"),
                                              client_ip=client_ip))
        elif status in ("mfa_required", "challenge"):
            eventmanager.send_event(
                etype=ChainEventType.MfaChallengeRequired,
                data=MfaChallengeEventData(username=username or "",
                                           factors_available=result.get("factors_available") or []))
    except Exception as e:  # noqa: BLE001
        logger.error(f"多步登录观测事件发送失败：{str(e)}")


def _flow_http(result: dict, username: Optional[str], request: Request) -> dict:
    """把服务层结构化结果折成 HTTP 响应：失败 → 401（detail 已脱敏）；其余 → 200 + 状态体。"""
    client_ip = request.client.host if request.client else None
    emit_auth_event(result, username, client_ip)
    if result.get("status") == "failure":
        raise HTTPException(status_code=401,
                            detail=redact_reason(result.get("error") or "auth_failed"))
    return result


@router.post("/flow/begin", summary="开始多步登录流程")
def flow_begin(body: FlowBeginRequest, request: Request) -> dict:
    """开始一条可组合、可多轮的登录流程。返回 ``status``：success（带 token）/ mfa_required /
    challenge / continue。后续以返回的 ``flow_token`` 调用 ``/auth/flow/advance`` 推进。"""
    result = _build_flow_service().begin(body)
    return _flow_http(result, body.username, request)


@router.post("/flow/advance", summary="推进多步登录流程")
def flow_advance(body: FlowAdvanceRequest, request: Request) -> dict:
    """凭 ``flow_token`` 推进下一步（提交因子码 / 挑战应答 / 后补凭证）。"""
    result = _build_flow_service().advance(body.flow_token, body)
    return _flow_http(result, body.username, request)


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


def _sso_redirect_back(success_redirect: str, **query: Any) -> RedirectResponse:
    """重定向回前端，按 SSO flow 结果带不同 query：成功 ``?ticket=``（前端再 /auth/exchange 换 Token）、
    需 MFA ``?flow_token=&sso_mfa=1``（前端复用 /auth/flow/advance 补因子）、失败 ``?sso_error=``。"""
    from urllib.parse import urlencode
    # 保底再过滤一次，确保任何调用方传入的 success_redirect 均为站内相对路径
    success_redirect = _safe_relative(success_redirect)
    base = settings.MP_DOMAIN(success_redirect) or success_redirect
    query = {k: v for k, v in query.items() if v is not None}
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


def _build_sso_flow_service(provider: Any, request: Request):
    """实时装配 SSO 多步登录服务：RedirectStep 凭证步 → 条件 MFA，成功铸一次性 ticket 交浏览器。

    与 ``/access-token`` / ``/auth/flow`` 共用同一批因子与 ``factors_for_user``，故 SSO 用户的 MFA
    与密码登录完全一致；``issue_ticket`` 铸票（浏览器 GET 导航无法回 JSON body），前端再 /auth/exchange 换 Token。
    """
    from app.core.auth.flow_registry import get_auth_flow
    from app.core.auth_bridge import create_plugin_auth_ticket
    from app.service.auth.flow_steps import FactorStep
    from app.service.auth.orchestrator import factors_for_user
    from app.service.auth.sso_flow import build_sso_flow_service

    default_spec = get_auth_flow("default")
    mfa_requirement = (lambda steps: default_spec.mfa_requirement(steps)) if default_spec else None
    return build_sso_flow_service(
        provider,
        flow_store=_FLOW_STORE,
        factors_for_user=lambda user: [FactorStep(f) for f in factors_for_user(user)],
        load_user=lambda uid: User.get(db=None, rid=uid),
        issue_ticket=lambda user: create_plugin_auth_ticket(
            user_id=user.id, provider_id=provider.provider_id,
            metadata={"sso_provider": provider.provider_id}),
        mfa_requirement=mfa_requirement,
    )


@router.get("/sso/{provider_id}/callback", summary="SSO 登录回调")
def sso_callback(provider_id: str, request: Request, code: str = "", state: str = "") -> RedirectResponse:
    """处理 IdP 回调：经统一流程引擎完成 CSRF 校验 / 换身份 / 解析建号 / **条件 MFA**，再重定向回前端。

    无 MFA → ``?ticket=``（前端再 /auth/exchange 换 Token）；该用户启用了 MFA → ``?flow_token=&sso_mfa=1``
    （前端复用 /auth/flow/advance 补第二因子）；失败 → ``?sso_error=``。
    """
    provider = sso.get_auth_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="未知的登录提供方")
    success_redirect = _safe_relative(getattr(provider, "success_redirect", "/"))
    svc = _build_sso_flow_service(provider, request)
    result = svc.begin(types.SimpleNamespace(
        step_id=provider_id, code=code, state=state,
        redirect_uri=_sso_redirect_uri(provider_id, request)))
    emit_auth_event(result, getattr(provider, "provider_name", provider_id),
                    request.client.host if request.client else None)
    return _sso_redirect_back(success_redirect, **sso_callback_query(result))
