# -*- coding: utf-8 -*-
"""多步登录服务的装配桥：按全局步骤注册表与 SSO 重定向注册表实时拼装 ``FlowService``。

凭证步、第二因子步、流程形状（MFA 组合策略）与外部依赖（流程状态存储、内建凭证 id 集合、
内建因子构造、回调 URI 构造）全部由调用方注入，本模块只负责把它们组合成统一多步登录服务。
"""
from typing import Any, Callable, Optional

from fastapi import Request

from app.core.config import settings


def build_flow_service(
    *,
    request: Optional[Request],
    issue_token: Optional[Any],
    flow_store: Any,
    credential_step_kinds: set,
    builtin_credential_ids: frozenset,
    builtin_factor_steps: Callable[[Any], list],
    flow_callback_uri: Callable[[Optional[Request]], str],
    load_user: Callable[[Any], Any],
    default_issue_token: Callable[[Any], Any],
    logger: Any,
):
    """按全局步骤注册表（``all_auth_steps()``）+ SSO 重定向注册表实时装配多步登录服务（装配桥）。

    - 凭证步 = 本地 ``PasswordStep`` + 注册表中 step_kind ∈ ``credential_step_kinds`` 的插件步（排除冒充内建 id 者）
      + SSO 注册表（``redirect.registered_provider_ids()``）每个提供方包装的 ``RedirectStep``
      （把 SSO 注册表桥接进统一流程；与 ``all_auth_steps()`` 的 redirect 步按 step_id 去重，
      内建 / all_auth_steps 优先）；
    - 第二因子步 = 该用户的 per-user 内建因子 + 注册表中 step_kind=="factor" 的插件步（applies_to 自行 per-user 过滤）。

    :param request: 当前请求（用于推导 SSO 回调 redirect_uri；非端点直调时可为 None）
    :param issue_token: 成功后铸 Token 的可注入覆盖（缺省用 ``build_token_response``；SSO 薄桥注入"铸一次性
        ticket"以经 ``/auth/exchange`` 兑换，因浏览器导航无法回 JSON）
    :param flow_store: 多步登录流程状态存储
    :param credential_step_kinds: 归入凭证阶段（解析用户）的 step_kind 集合
    :param builtin_credential_ids: 受信内建凭证 id 集合（可直携 user_id，且禁止插件冒充）
    :param builtin_factor_steps: 给定 user 返回其 per-user 内建第二因子步列表的构造函数
    :param flow_callback_uri: 给定 request 构造统一流程 SSO 回调 redirect_uri 的函数
    :param load_user: 给定 user_id 加载本地用户的函数
    :param default_issue_token: 缺省铸 Token 的函数（``issue_token`` 为空时使用）
    :param logger: 装配期告警（凭证步冒充内建 id / SSO 影子化命名冲突）所用日志器
    :return: 装配完成的 ``FlowService``
    """
    from app.core.auth import redirect as sso_redirect
    from app.core.auth.flow_registry import get_auth_flow
    from app.core.auth.steps import all_auth_steps
    from app.service.auth.flow_service import FlowService
    from app.service.auth.flow_steps import (
        AuxiliaryCredentialStep, PasskeyLoginStep, PasswordStep, RedirectStep, make_identity_resolver)
    from app.service.auth.provisioning import default_deps

    deps = default_deps()
    steps = all_auth_steps()

    # 受信 id 集先于过滤器计算：「可直接携 user_id」的内建 id == 「插件不得冒充」的排除 id，由构造保证二者一致。
    # frozenset 来源 builtin_credential_ids 防意外 mutate。
    trusted_step_ids = builtin_credential_ids | ({"auxiliary"} if settings.AUXILIARY_AUTH_ENABLE else set())

    # PasskeyLoginStep 为内建受信凭证步（opt-in，仅 flow="system:passkey" 选中时参与）：
    # 解析本地 User 受信直落 user_id（其 step_id 已在 trusted_step_ids 内）。
    credential_steps = [PasswordStep(), PasskeyLoginStep()]
    for s in steps:
        if getattr(s, "step_kind", None) not in credential_step_kinds:
            continue
        sid = getattr(s, "step_id", None)
        if sid in trusted_step_ids:
            # 插件声称受信内建 id（如 "auxiliary"）→ 拦截并告警；冒充者不纳入凭证步，
            # 杜绝插件以受信 id 绕过 owner 分流护栏直接落 user_id（镜像 SSO shadow 告警逻辑）。
            logger.warning(
                f"插件凭证步 '{sid}' 声称受信内建 step_id，已拒绝注册："
                f"插件不得冒充内建凭证步以绕过 owner 分流护栏"
            )
            continue
        credential_steps.append(s)

    # 媒体服务器辅助认证（AUXILIARY_AUTH_ENABLE）：以受信内建凭证步恢复（密码失败后 OR 回落）。
    # 其建号走媒体服务器专属 provisioning（_process_auth_success），须纳入 trusted_step_ids 方被引擎接受。
    if settings.AUXILIARY_AUTH_ENABLE:
        credential_steps.append(AuxiliaryCredentialStep())

    # 桥接 SSO 注册表为统一流程的 RedirectStep（自签 flow 绑定 state + /auth/flow/callback 回调）；
    # 按 step_id 去重：已在内建 / all_auth_steps 出现者优先（绝不被 SSO 覆盖，防内建受信步被影子化）。
    existing_ids = {getattr(s, "step_id", None) for s in credential_steps}
    for pid in sso_redirect.registered_provider_ids():
        if pid in existing_ids:
            # all_auth_steps() 的某凭证步已占用此 step_id → 该 SSO provider 被影子化、不纳入统一流程，
            # 告警以便运维侦测命名冲突。
            logger.warning(
                f"SSO provider '{pid}' 被同名凭证步影子化，未纳入统一登录流程；请检查 step_id 冲突")
            continue
        provider = sso_redirect.get_auth_provider(pid)
        if provider is None:
            continue
        credential_steps.append(RedirectStep(
            provider,
            issue_state=sso_redirect.issue_state,
            redirect_uri=lambda: flow_callback_uri(request),
            consume_state=sso_redirect.consume_state,
            deps=deps))
        existing_ids.add(pid)

    plugin_factor_steps = [s for s in steps if getattr(s, "step_kind", None) == "factor"]

    # 流程形状可插拔：若有插件注册了名为 "default" 的流程规格（如 N-of-M 强 MFA），用其组合策略；
    # 否则沿用默认 AnyOf（任一因子，复现 v2 OR）。注册期 verify_flow_spec_contract 已拒绝"空真"规格，
    # 杜绝插件以 default 规格 vacuous 绕过 MFA。
    default_spec = get_auth_flow("default")
    mfa_requirement = (lambda steps: default_spec.mfa_requirement(steps)) if default_spec else None
    return FlowService(
        flow_store=flow_store,
        credential_steps=credential_steps,
        factor_steps_for=lambda user: builtin_factor_steps(user) + plugin_factor_steps,
        load_user=load_user,
        issue_token=issue_token or default_issue_token,
        mfa_requirement=mfa_requirement,
        identity_resolver=make_identity_resolver(deps),
        trusted_step_ids=trusted_step_ids,
    )
