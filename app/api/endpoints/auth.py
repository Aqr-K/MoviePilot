import types
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app import schemas
from app.core import security
from app.core.auth import redirect as sso
from app.core.auth_bridge import build_token_response, consume_plugin_auth_ticket
from app.core.config import settings
from app.core.event import eventmanager
from app.helper.plugin_manager import PluginManager
from app.log import logger
from app.schemas import RateLimitExceededException
from app.schemas.event import AuthObservationEventData, MfaChallengeEventData
from app.schemas.types import ChainEventType
from app.service.auth.flow_engine import FlowStore
from app.service.auth.flow_service import redact_reason
from app.utils.limit import KeyedWindowRateLimiter
from app.db.models.passkey import PassKey
from app.db.models.user import User

router = APIRouter()

# 统一登录流程入口（所有 SSO/重定向提供方经此进入与密码/因子同一条多步流程）
_FLOW_BEGIN_PATH = "/api/v1/auth/flow/begin"

# 多步登录流程状态存储（进程级，跨请求承载未完成的流程；重启失效=重新登录，可接受）
_FLOW_STORE = FlowStore()

# 多步推进端点限流：10 次 / 60 秒 / (ip+username)，进程级；多实例需共享后端（Redis）
# Chosen limit: 10 attempts / 60 s mirrors the /access-token limit (KISS, same policy)
_auth_advance_rate_limiter = KeyedWindowRateLimiter(max_calls=10, window_seconds=60)


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
            # 经统一流程入口发起：前端 POST _FLOW_BEGIN_PATH + body {"flow": "system:passkey"}
            "flow": "system:passkey",
            "login_url": _FLOW_BEGIN_PATH,
        }
    ]


def _registered_sso_providers() -> list[dict[str, Any]]:
    """
    由 app.core.auth.redirect 注册表（provides_auth_providers）派生登录入口摘要。

    每个注册提供方经统一多步流程入口登录：前端 POST ``/api/v1/auth/flow/begin`` 并携带
    ``{"flow": "<provider_id>"}`` 定向到该重定向步，框架据此下发跳转挑战（authorize_url）并统一驱动
    OAuth 回调，无需插件再声明 `/sso/{id}/login` 端点。

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
            # 统一流程入口（POST-only）：前端须以 POST _FLOW_BEGIN_PATH + body {"flow": pid} 发起，
            # 直接 GET login_url 会 405；使用 "flow" 字段作为步骤选择器。
            "login_url": _FLOW_BEGIN_PATH,
            "flow": pid,
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
def auth_exchange(body: schemas.AuthExchangeRequest) -> schemas.Token:
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


# 装配桥按 step_kind 切分全局步骤注册表：以下种归入【凭证阶段】（解析用户），其余 "factor" 归第二因子阶段。
_CREDENTIAL_STEP_KINDS = {"credential", "directory", "federated_direct", "redirect"}
# 防内建 id 冒充：排除任何声称内建 id 的插件凭证步，杜绝插件以 "password" / "system:passkey"
# 影子化/继承受信而直接落 user_id 绕过 owner 分流。内建受信步由本地 PasswordStep 与 PasskeyLoginStep 提供。
# frozenset（不可变）防止调用方意外 mutate 该集合来弱化 owner-routing 护栏。
_BUILTIN_CREDENTIAL_IDS: frozenset[str] = frozenset({"password", "system:passkey"})


def _builtin_factor_steps(user) -> list:
    """该用户的 per-user 内建第二因子（OTP/PassKey，经闭包绑定到本 user）包装为 ``FactorStep``。

    只构内建因子——插件因子改由 ``all_auth_steps()`` 的 "factor" 种步骤注入，故此处不含插件因子，
    避免与注册表里的插件因子双计。
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


def _build_flow_service(request: Optional[Request] = None, *, issue_token: Optional[Any] = None):
    """按全局步骤注册表 + SSO 重定向注册表实时装配多步登录服务（端点薄壳）。

    装配主体在 ``app.service.auth.assembler.build_flow_service``；本壳把端点侧依赖（流程状态存储、
    凭证 step_kind 集、受信内建 id 集、内建因子构造、回调 URI 构造、用户加载、缺省发 Token、日志器）
    按模块全局名在**调用时**取并透传，确保测试对这些模块级名字的 monkeypatch 仍被读到。

    :param request: 当前请求（用于推导 SSO 回调 redirect_uri；非端点直调时可为 None）
    :param issue_token: 成功后铸 Token 的可注入覆盖（缺省由装配桥用 ``build_token_response``）
    :return: 装配完成的 ``FlowService``
    """
    from app.service.auth.assembler import build_flow_service
    return build_flow_service(
        request=request,
        issue_token=issue_token,
        flow_store=_FLOW_STORE,
        credential_step_kinds=_CREDENTIAL_STEP_KINDS,
        builtin_credential_ids=_BUILTIN_CREDENTIAL_IDS,
        builtin_factor_steps=_builtin_factor_steps,
        flow_callback_uri=_flow_callback_uri,
        load_user=lambda uid: User.get(db=None, rid=uid),
        default_issue_token=build_token_response,
        logger=logger,
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


def _set_flow_resource_cookie(token: Any, request: Request, response: Optional[Response]) -> None:
    """流程成功后写入资源 Cookie（浏览器侧插件静态文件鉴权所需），与 /access-token 行为一致。

    仅当 ``response`` 可用且 ``token`` 为标准 ``Token``（含 user_id；SSO 薄桥铸的 ticket 字符串不在此列）
    时设置；复用 login.py 同一 helper（``set_or_refresh_resource_token_cookie``），单一来源。
    """
    if response is None or token is None or not hasattr(token, "user_id"):
        return
    try:
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
    except Exception as e:  # noqa: BLE001 —— Cookie 写入失败绝不阻断已成功的登录
        logger.error(f"流程登录写入资源 Cookie 失败：{str(e)}")


def _flow_http(result: dict, username: Optional[str], request: Request,
               response: Optional[Response] = None) -> dict:
    """把服务层结构化结果折成 HTTP 响应：失败 → 401（detail 已脱敏）；其余 → 200 + 状态体。

    成功且提供 ``response`` 时，附带写入资源 Cookie（与 /access-token 一致）。"""
    client_ip = request.client.host if request.client else None
    emit_auth_event(result, username, client_ip)
    if result.get("status") == "failure":
        raise HTTPException(status_code=401,
                            detail=redact_reason(result.get("error") or "auth_failed"))
    if result.get("status") == "success":
        _set_flow_resource_cookie(result.get("token"), request, response)
    return result


def _check_flow_rate_limit(request: Request, username: Optional[str]) -> None:
    """未认证口令校验端点防暴力破解（CWE-307）：按 (ip+username) 滑窗限流后放行，超阈值抛 429。

    /flow/begin 与 /flow/advance 共用同一限流器实例（``_auth_advance_rate_limiter``）与异常类型
    （``RateLimitExceededException``），策略与 /access-token 一致（10 次 / 60 秒），由本函数单一来源保证。
    ``username`` 为空（纯枚举/SSO begin）时退化为按 ip 限流。"""
    client_ip = request.client.host if request.client else "unknown"
    rl_key = f"{client_ip}:{username}" if username else client_ip
    try:
        _auth_advance_rate_limiter.check(rl_key)
    except RateLimitExceededException:
        raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")


@router.post("/flow/begin", summary="开始多步登录流程")
def flow_begin(body: schemas.FlowBeginRequest, request: Request, response: Response = None) -> dict:
    """开始一条可组合、可多轮的登录流程。返回 ``status``：success（带 token）/ mfa_required /
    challenge / continue。后续以返回的 ``flow_token`` 调用 ``/auth/flow/advance`` 推进。

    携带 ``flow="<provider_id>"`` 时定向到该 SSO/重定向步，直接下发跳转挑战（authorize_url），SSO 由此
    进入与密码/因子同一条统一流程；浏览器 302 至 IdP 后经 ``/auth/flow/callback`` 薄桥回灌推进。

    入口按 (ip+username) 限流（与 /flow/advance、/access-token 同策略），防止口令暴力穷举（CWE-307）。
    成功时写入资源 Cookie（FastAPI 注入 ``response``；与 /access-token 一致）。"""
    _check_flow_rate_limit(request, body.username)
    result = _build_flow_service(request).begin(body)
    return _flow_http(result, body.username, request, response)


@router.post("/flow/advance", summary="推进多步登录流程")
def flow_advance(body: schemas.FlowAdvanceRequest, request: Request, response: Response = None) -> dict:
    """凭 ``flow_token`` 推进下一步（提交因子码 / 挑战应答 / 后补凭证）。

    成功时写入资源 Cookie（FastAPI 注入 ``response``；与 /access-token 一致）。"""
    _check_flow_rate_limit(request, body.username)
    result = _build_flow_service().advance(body.flow_token, body)
    return _flow_http(result, body.username, request, response)


def sso_callback_query(result: dict) -> dict:
    """SSO flow 结果 → 回前端跳转的 query 参数（HTTP 无关，便于单测）。

    - ``success``      → ``{ticket}``（前端再 ``/auth/exchange`` 换 Token）；
    - ``mfa_required`` → ``{flow_token, sso_mfa:"1"}``（前端复用 ``/auth/flow/advance`` 补第二因子）；
    - 其它 / 失败      → ``{sso_error}``。
    """
    status = result.get("status")
    if status == "success":
        return {"ticket": result.get("token")}
    if status == "mfa_required":
        return {"flow_token": result.get("flow_token"), "sso_mfa": "1"}
    return {"sso_error": result.get("error") or "认证失败"}


@router.get("/flow/callback", summary="SSO 统一流程回调薄桥")
def flow_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    """SSO IdP 回调薄桥：把回调应答回灌**统一流程引擎**推进（SSO 与密码/因子同一条流程）。

    薄桥**消费一次** CSRF state 取回 flow_token（CSRF 校验单一来源），再经 ``state_payload`` 透传给
    RedirectStep（本步不二次消费）→ 引擎完成换身份 / 解析建号 / **条件 MFA**：
      - 成功 → 铸一次性 ticket（浏览器导航无法回 JSON Token；前端再 /auth/exchange 换 Token），``?ticket=``；
      - 需 MFA → ``?flow_token=&sso_mfa=1``（前端复用 /auth/flow/advance 补第二因子，flow_token 非 Token，低风险）；
      - 失败 / 未知 state → ``?sso_error=``。flow_token / Token 绝不随成功跳转入 URL。
    """
    from app.core.auth.redirect import consume_state
    from app.core.auth_bridge import create_plugin_auth_ticket

    # IdP 拒绝/取消（?error=...，无 code）→ 快速失败：不消费 state（任其 TTL 过期）、不推进流程，
    # 杜绝空 code 在引擎里铸新孤儿 state、churn 状态存储。
    if not code:
        return _sso_redirect_back("/", sso_error="invalid_code")

    payload = consume_state(state)
    if not payload or not payload.get("flow_token"):
        return _sso_redirect_back("/", sso_error="invalid_state")
    provider_id = payload.get("provider_id")
    provider = sso.get_auth_provider(provider_id)
    if provider is None:
        # state 合法但 provider 已卸载 → 无对应 RedirectStep 可推进，安全返回失败
        return _sso_redirect_back("/", sso_error="invalid_state")
    success_redirect = _safe_relative(getattr(provider, "success_redirect", "/"))

    submission = types.SimpleNamespace(
        code=code, state=state, state_payload=payload,
        step_id=provider_id, redirect_uri=_flow_callback_uri(request))
    svc = _build_flow_service(request, issue_token=lambda user: create_plugin_auth_ticket(
        user_id=user.id, provider_id=provider_id,
        metadata={"sso_provider": provider_id}))
    result = svc.advance(payload["flow_token"], submission)
    emit_auth_event(result, getattr(provider, "provider_name", provider_id),
                    request.client.host if request.client else None)
    return _sso_redirect_back(success_redirect, **sso_callback_query(result))


# 统一流程 SSO 回调路径（所有 provider 共用同一回调，由 state 内绑定的 provider_id 路由）
_FLOW_CALLBACK_PATH = "/api/v1/auth/flow/callback"


def _flow_callback_uri(request: Optional[Request] = None) -> str:
    """构造统一流程 SSO 回调 redirect_uri（须与签发授权时一致）：优先 APP_DOMAIN，否则从请求 Host 推导。

    签发（begin）与回调（callback）须用同一 redirect_uri 才能完成 OAuth 换码；配 APP_DOMAIN 时两侧恒等，
    未配则各自据请求 Host 推导（同域同 Host → 一致）。无 request（如非端点直调）时回退相对路径。"""
    domain_url = settings.MP_DOMAIN(_FLOW_CALLBACK_PATH)
    if domain_url:
        return domain_url
    if request is not None:
        logger.warning("统一 SSO 回调未配置 APP_DOMAIN，回退用请求 Host 推导 redirect_uri，存在 Host 头注入风险")
        return f"{str(request.base_url).rstrip('/')}{_FLOW_CALLBACK_PATH}"
    return _FLOW_CALLBACK_PATH


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
