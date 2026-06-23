# -*- coding: utf-8 -*-
"""
身份 → 本地用户 provisioning（带安全护栏）。

忠实泛化 ``app/helper/sso.py._resolve_user`` 的护栏，供**主认证 provider**（LDAP/AD/RADIUS/
OIDC-ROPC 等 ``ICredentialProvider``）解析/建号复用。审计点名此处为最高正确性风险，故：
  - **C-1**：``auto_create`` 时，派生用户名若被一个**无任何身份绑定**的同名账号占用 → 拒绝接管
    （防接管管理员手建的非外部账号）；
  - **B-4**：派生用户名被**已禁用**的同名残留账号占用 → 拒绝复用（防绕过封禁）；
  - 绑定为权威主键 ``(provider_id, subject)``，外部用户名仅作快照；建号一律非管理员、随机密码；
  - 并发首登致绑定冲突时回退到已存在的绑定用户。

DB 协作经 ``ProvisioningDeps`` 端口注入（生产用 ``default_deps()`` 接 SsoIdentity/User/UserOper；
单测注入内存 fake），保持本模块逻辑可独立特征测试。**本模块在 PR4 为休眠态**（无 provider 注册）。
"""
import re
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from app.log import logger

# subject 合法字符集（与 helper/sso 一致：字母数字与 . _ -，最长 64，首尾为字母数字）
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,62}[A-Za-z0-9])?$")
# 外部托管账号用户名前缀（与本地账号命名空间隔离，沿用 SSO 约定以共享绑定语义）
_USERNAME_PREFIX = "sso_"


@dataclass
class ProvisioningDeps:
    """provisioning 的 DB 协作端口（生产由 ``default_deps`` 注入，单测注入 fake）。"""

    get_binding: Callable[[str, str], Optional[Any]]              # (provider_id, subject) -> user_id | None
    get_user_by_id: Callable[[Any], Optional[Any]]               # (user_id) -> user | None（user 具 .is_active）
    get_user_by_name: Callable[[str], Optional[Any]]            # (name) -> user | None（user 具 .id/.is_active）
    create_user: Callable[..., None]                            # (name=, avatar=) -> None
    list_bindings_for_user: Callable[[Any], List[Any]]          # (user_id) -> 绑定列表（truthy 表示有绑定）
    create_binding: Callable[..., None]                         # (provider_id=, subject=, user_id=, username=) -> None（冲突可抛）


def resolve_or_create(provider_id: str, *, subject: str, username: Optional[str] = None,
                      avatar: Optional[str] = None, auto_create: bool,
                      deps: ProvisioningDeps) -> Optional[Any]:
    """按稳定 ``subject`` 把外部身份解析/建号为本地用户（改名安全 + C-1/B-4 护栏）。

    返回本地用户对象；任一护栏触发或失败返回 ``None``。
    """
    subject = (subject or "").strip()
    if not _SUBJECT_RE.match(subject):
        logger.warning(f"provider {provider_id} 返回非法 subject，已拒绝")
        return None

    # 1) 权威解析：按 (provider_id, subject) 绑定
    bound_user_id = deps.get_binding(provider_id, subject)
    if bound_user_id is not None:
        user = deps.get_user_by_id(bound_user_id)
        if user is None or not getattr(user, "is_active", False):
            logger.warning(f"provider {provider_id}:{subject} 绑定用户不存在或已禁用，拒绝登录")
            return None
        return user

    # 2) 未绑定：按 auto_create 门控
    if not auto_create:
        logger.info(f"身份 {provider_id}:{subject} 未绑定且未开启自动建号，拒绝登录")
        return None

    local_username = f"{_USERNAME_PREFIX}{provider_id}_{subject}"
    user = deps.get_user_by_name(local_username)
    if user is not None:
        if not getattr(user, "is_active", False):
            logger.warning(f"同名残留用户 {local_username} 已禁用，拒绝复用（B-4）")
            return None
        if not deps.list_bindings_for_user(user.id):
            logger.warning(f"派生用户名 {local_username} 被非外部账号占用，拒绝接管（C-1）")
            return None
    else:
        deps.create_user(name=local_username, avatar=avatar)
        user = deps.get_user_by_name(local_username)
        if user is None:
            logger.error(f"新建本地用户 {local_username} 失败")
            return None

    # 3) 落绑定（subject 为权威主键）；并发首登致冲突时回退到已存在绑定
    try:
        deps.create_binding(provider_id=provider_id, subject=subject,
                            user_id=user.id, username=username or None)
    except Exception as e:  # noqa: BLE001 —— 任何 DB 异常都走并发回退，绝不向上抛
        existing_uid = deps.get_binding(provider_id, subject)
        if existing_uid is not None:
            bound = deps.get_user_by_id(existing_uid)
            if bound is not None and getattr(bound, "is_active", False):
                logger.info(f"身份 {provider_id}:{subject} 已被并发绑定，复用绑定用户")
                return bound
        logger.error(f"绑定 {provider_id}:{subject} 失败：{str(e)}")
        return None
    logger.info(f"首次登录，已创建/绑定本地用户 {local_username}（{provider_id}:{subject}）")
    return user


def default_deps() -> ProvisioningDeps:
    """生产 ``ProvisioningDeps``：接 SsoIdentity / User / UserOper（行为对齐 helper/sso）。"""
    import secrets

    from app.core.security import get_password_hash
    from app.db.models.ssoidentity import SsoIdentity
    from app.db.models.user import User
    from app.db.user_oper import UserOper

    def get_binding(provider_id: str, subject: str):
        binding = SsoIdentity.get_by_subject(db=None, provider_id=provider_id, subject=subject)
        return binding.user_id if binding else None

    def get_user_by_id(user_id):
        return User.get(db=None, rid=user_id)

    def get_user_by_name(name: str):
        return UserOper().get_by_name(name=name)

    def create_user(name: str, avatar=None):
        UserOper().add(name=name, avatar=avatar, is_active=True, is_superuser=False,
                       hashed_password=get_password_hash(secrets.token_urlsafe(16)))

    def list_bindings_for_user(user_id):
        return SsoIdentity.list_by_user(db=None, user_id=user_id)

    def create_binding(provider_id: str, subject: str, user_id, username=None):
        SsoIdentity(provider_id=provider_id, subject=subject,
                    user_id=user_id, username=username or None).create(db=None)

    return ProvisioningDeps(
        get_binding=get_binding,
        get_user_by_id=get_user_by_id,
        get_user_by_name=get_user_by_name,
        create_user=create_user,
        list_bindings_for_user=list_bindings_for_user,
        create_binding=create_binding,
    )
