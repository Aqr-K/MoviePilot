# -*- coding: utf-8 -*-
"""
SSO 登录流程编排（helper 层，可碰 db）。

承接 app.core.sso 的 db-free 核心（state/registry/contract），把每个 SSO 插件原本要重复实现的
「授权码校验 → 外部身份 → 本地用户解析/建号 → 铸票」这套样板（G3）统一在此实现：插件交出的
IAuthProvider 只负责 IdP 特定的 authorize_url / fetch_identity，其余全由框架代劳。
"""
import re
import secrets
from typing import Optional, Tuple

from app.core import sso as sso_core
from app.core.auth_bridge import create_plugin_auth_ticket
from app.core.security import get_password_hash
from app.db.user_oper import UserOper
from app.log import logger

# 授权码合法字符集（边界输入校验，防注入下游/日志）
_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")
# 外部用户名合法字符集（保守集合：字母数字与 . _ -，最长 64）
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
# 本地 SSO 用户名前缀（与本地账号命名空间隔离）
_USERNAME_PREFIX = "sso_"


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
    if not code or not _CODE_RE.match(code):
        return None, "invalid_code"
    # 3) 换取外部身份（提供方异常一律安全失败）
    try:
        identity = provider.fetch_identity(code, redirect_uri)
    except Exception as e:
        logger.error(f"SSO 提供方 {provider_id} 换取身份异常：{str(e)}")
        return None, "fetch_identity_failed"
    if not identity or not getattr(identity, "username", None):
        return None, "fetch_identity_failed"
    # 4) 解析/建本地用户
    user = _resolve_user(provider_id, identity, auto_create)
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


def _resolve_user(provider_id: str, identity, auto_create: bool):
    """
    将外部身份映射为本地用户。

    安全：用户名 = ``sso_{provider_id}_{外部用户名}``，按提供方+前缀双重命名空间隔离，杜绝与本地账号
    或跨提供方撞名劫持；首次登录是否建号由 auto_create 门控（默认关），自动建号一律非管理员、随机密码。
    """
    raw = getattr(identity, "username", "") or ""
    if not _USERNAME_RE.match(raw):
        logger.warning(f"SSO 提供方 {provider_id} 返回非法格式的用户名，已拒绝")
        return None
    username = f"{_USERNAME_PREFIX}{provider_id}_{raw}"
    useroper = UserOper()
    user = useroper.get_by_name(name=username)
    if user:
        if not user.is_active:
            logger.warning(f"SSO 用户 {username} 已被禁用，拒绝登录")
            return None
        return user
    if not auto_create:
        logger.info(f"SSO 用户 {username} 不存在且未开启自动建号，拒绝登录")
        return None
    useroper.add(
        name=username,
        avatar=getattr(identity, "avatar", None),
        is_active=True,
        is_superuser=False,
        hashed_password=get_password_hash(secrets.token_urlsafe(16)),
    )
    logger.info(f"SSO 首次登录，已创建本地用户：{username}")
    return useroper.get_by_name(name=username)
