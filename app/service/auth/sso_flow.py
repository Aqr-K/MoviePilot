# -*- coding: utf-8 -*-
"""SSO 重定向登录的流程装配 —— 把 SSO 收进统一的 ``FlowService``（取代 helper/sso 的 ticket 旁路）。

callback 端点用本模块把 SSO 当作一条「仅含 ``RedirectStep`` 凭证步」的登录流程跑完整引擎：
解析外部身份后自动接「条件 MFA」阶段，与密码 / 凭据 provider 登录走**同一套编排**（不再绕过 MFA）。
成功铸一次性 ticket（浏览器 GET 导航无法回 JSON body，故经票据交前端，前端再 ``/auth/exchange`` 换 Token）。
"""
from typing import Any, Callable, List, Optional

from app.core.auth.flow import AuthRequirement
from app.service.auth.flow_service import FlowService
from app.service.auth.flow_steps import RedirectStep


def build_sso_flow_service(provider: Any, *, flow_store: Any,
                           factors_for_user: Callable[[Any], List[Any]],
                           load_user: Callable[[Any], Optional[Any]],
                           issue_ticket: Callable[[Any], Any],
                           mfa_requirement: Optional[Callable[[List[Any]], AuthRequirement]] = None,
                           deps: Any = None,
                           consume_state: Optional[Callable[[Optional[str]], bool]] = None) -> FlowService:
    """装配以单个 SSO ``provider`` 为唯一凭证步的多步登录服务。

    ``issue_ticket(user) -> ticket``：SSO 成功铸一次性票据交浏览器（而非直接产 Token）；
    ``deps`` / ``consume_state`` 缺省接生产单例（``default_deps`` / ``redirect.consume_state``），单测可注入。
    """
    sso_step = RedirectStep(provider, consume_state=consume_state, deps=deps)
    return FlowService(
        flow_store=flow_store,
        credential_steps=[sso_step],
        factor_steps_for=factors_for_user,
        load_user=load_user,
        issue_token=issue_ticket,
        mfa_requirement=mfa_requirement,
    )


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
