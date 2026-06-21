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
from app.db.models.ssoidentity import SsoIdentity
from app.db.models.user import User
from app.db.user_oper import UserOper
from app.log import logger

# 授权码合法字符集（边界输入校验，防注入下游/日志）
_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")
# subject 合法字符集（用户名安全集合：字母数字与 . _ -，最长 64）。subject 是身份主键，
# 同时用于派生本地用户名 sso_{provider_id}_{subject}；provider_id 不含分隔符（核心契约保证）
# 故 (provider_id, subject) → 用户名 单射，无撞名。插件须返回此集合内的稳定 subject。
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,62}[A-Za-z0-9])?$")
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
    按稳定 subject 将外部身份映射到本地用户（改名安全）。

    解析以 SsoIdentity 绑定表 (provider_id, subject) 为权威：命中即返回绑定的本地用户；
    未绑定且开启 auto_create 时新建用户并落绑定，否则拒绝。外部用户名（可变）只作快照，不参与解析。

    安全：subject 经 _SUBJECT_RE 校验；本地用户名 ``sso_{provider_id}_{subject}`` 由稳定主键派生，
    provider_id 不含分隔符（核心契约保证）故映射单射、无跨提供方撞名；建号一律非管理员、随机密码。
    """
    subject = (getattr(identity, "subject", "") or "").strip()
    if not _SUBJECT_RE.match(subject):
        logger.warning(f"SSO 提供方 {provider_id} 返回非法格式的 subject，已拒绝")
        return None
    # 1) 权威解析：按 (provider_id, subject) 查绑定
    binding = SsoIdentity.get_by_subject(db=None, provider_id=provider_id, subject=subject)
    if binding:
        user = User.get(db=None, rid=binding.user_id)
        if not user or not user.is_active:
            logger.warning(f"SSO 绑定用户 {binding.user_id}（{provider_id}:{subject}）不存在或已禁用，拒绝登录")
            return None
        return user
    # 2) 未绑定：按 auto_create 门控建号
    if not auto_create:
        logger.info(f"SSO 身份 {provider_id}:{subject} 未绑定且未开启自动建号，拒绝登录")
        return None
    username = f"{_USERNAME_PREFIX}{provider_id}_{subject}"
    useroper = UserOper()
    # 用户名由稳定 subject 派生。同名用户已存在时，仅当其确为 SSO 托管账号（有任意身份绑定）且未禁用才复用，
    # 否则拒绝——避免接管管理员手建的同名非 SSO 账号（C-1），以及绕过对同名残留账号的封禁（B-4）。
    user = useroper.get_by_name(name=username)
    if user is not None:
        if not user.is_active:
            logger.warning(f"SSO 同名残留用户 {username} 已禁用，拒绝复用")
            return None
        if not SsoIdentity.list_by_user(db=None, user_id=user.id):
            logger.warning(f"SSO 派生用户名 {username} 被非 SSO 账号占用，拒绝接管")
            return None
    else:
        useroper.add(
            name=username,
            avatar=getattr(identity, "avatar", None),
            is_active=True,
            is_superuser=False,
            hashed_password=get_password_hash(secrets.token_urlsafe(16)),
        )
        user = useroper.get_by_name(name=username)
    if not user:
        logger.error(f"SSO 新建本地用户 {username} 失败")
        return None
    # 3) 落绑定（subject 为权威主键，外部用户名仅作快照）；并发首登致唯一键冲突时改用已存在绑定
    try:
        SsoIdentity(
            provider_id=provider_id,
            subject=subject,
            user_id=user.id,
            username=(getattr(identity, "username", None) or None),
        ).create(db=None)
    except Exception as e:
        existing = SsoIdentity.get_by_subject(db=None, provider_id=provider_id, subject=subject)
        if existing:
            bound = User.get(db=None, rid=existing.user_id)
            if bound and bound.is_active:
                logger.info(f"SSO 身份 {provider_id}:{subject} 已被并发绑定，复用绑定用户")
                return bound
        logger.error(f"SSO 绑定 {provider_id}:{subject} 失败：{str(e)}")
        return None
    logger.info(f"SSO 首次登录，已创建本地用户 {username} 并绑定 {provider_id}:{subject}")
    return user
