# -*- coding: utf-8 -*-
"""
SSO 登录流程编排（helper 层，可碰 db）。

承接 app.core.sso 的 db-free 核心（state/registry/contract），把每个 SSO 插件原本要重复实现的
「授权码校验 → 外部身份 → 本地用户解析/建号 → 铸票」这套样板（G3）统一在此实现：插件交出的
IAuthProvider 只负责 IdP 特定的 authorize_url / fetch_identity，其余全由框架代劳。
"""
from typing import Optional, Tuple

from app.core import sso as sso_core
from app.core.auth.identifiers import is_valid_code
from app.core.auth_bridge import create_plugin_auth_ticket
from app.log import logger
from app.service.auth.provisioning import default_deps, resolve_or_create


def begin_login(provider, redirect_uri: str) -> str:
    """签发 CSRF state 并返回 IdP 授权页 URL（框架统一持有 state）。"""
    state = sso_core.issue_state()
    return provider.authorize_url(state, redirect_uri)


def complete_login(provider, code: Optional[str], state: Optional[str], redirect_uri: str,
                   *, auto_create: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    完成回调：校验 state(CSRF) → 校验 code → 换外部身份 → 解析/建本地用户 → 铸票。

    返回 (ticket, error)：成功时 (票据, None)，失败时 (None, 错误码)。错误码语义化（invalid_state /
    invalid_code / fetch_identity_failed / user_not_provisioned），不泄露内部细节。
    """
    provider_id = getattr(provider, "provider_id", "?")
    # 1) CSRF：state 必须本服务签发、未过期、未用过（取即销毁）
    if not sso_core.consume_state(state):
        logger.warning(f"SSO 提供方 {provider_id} 回调 state 校验失败（CSRF 或已过期）")
        return None, "invalid_state"
    # 2) 边界校验授权码
    if not is_valid_code(code):
        return None, "invalid_code"
    # 3) 换取外部身份（提供方异常一律安全失败）
    try:
        identity = provider.fetch_identity(code, redirect_uri)
    except Exception as e:
        logger.error(f"SSO 提供方 {provider_id} 换取身份异常：{str(e)}")
        return None, "fetch_identity_failed"
    if not identity or not getattr(identity, "username", None):
        return None, "fetch_identity_failed"
    # 4) 解析/建本地用户：统一走守护式 provisioning（C-1/B-4/禁用/并发回退护栏单一来源于
    #    ``resolve_or_create``，不再于本模块重复实现）。
    user = resolve_or_create(
        provider_id,
        subject=(getattr(identity, "subject", "") or ""),
        username=getattr(identity, "username", None),
        avatar=getattr(identity, "avatar", None),
        auto_create=auto_create,
        deps=default_deps(),
    )
    if user is None:
        return None, "user_not_provisioned"
    # 5) 铸一次性票据（前端再 /auth/exchange 换 Token）
    ticket = create_plugin_auth_ticket(
        user_id=user.id,
        provider_id=provider_id,
        metadata={"sso_subject": getattr(identity, "subject", None)},
    )
    logger.info(f"SSO 提供方 {provider_id} 认证成功，用户：{user.name}，已签发登录票据")
    return ticket, None
