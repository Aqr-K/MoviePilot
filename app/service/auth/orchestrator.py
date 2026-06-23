# -*- coding: utf-8 -*-
"""
认证编排器 —— MFA 评估（PR2）。``resolve_identity`` 在 PR4 落地。

``evaluate_mfa`` 按 ``priority`` 升序遍历因子，折叠为统一 ``AuthResult``；
PR3 将以它替换 ``app/chain/user.py._verify_mfa``，并把 ``AuthResult`` 折叠回
``(True / "MFA_REQUIRED" / False)`` 以保持 v2 外部契约不变。
"""
from typing import Iterable, Optional

from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
from app.core.auth.outcome import AuthResult, ResolvedIdentity
from app.log import logger


def evaluate_mfa(user_ref: MfaUserRef, submission: Optional[MfaSubmission],
                 factors: Iterable) -> AuthResult:
    """评估 MFA（语义复现 ``_verify_mfa``）：

    - 无已注册因子 → ``success``；
    - 有因子但无有效提交 → ``mfa_required``（列出可用因子 id）；
    - 有提交 → 按 priority 依次验证：首个 ``allow``→``success`` / ``deny``→``failure``；
      若无因子能同步验证（如仅 PassKey）→ ``mfa_required``（前端走对应端点）。
    """
    ordered = sorted(factors, key=lambda f: getattr(f, "priority", 0))
    enrolled = [f for f in ordered if f.is_enrolled(user_ref)]
    if not enrolled:
        return AuthResult(kind="success")
    has_submission = bool(submission and (submission.code or submission.response))
    if not has_submission:
        return AuthResult(kind="mfa_required",
                          factors_available=[f.factor_id for f in enrolled])
    for factor in enrolled:
        result = factor.verify(user_ref, submission)
        if result.status == "allow":
            return AuthResult(kind="success")
        if result.status == "deny":
            return AuthResult(kind="failure")
        # not_enrolled / challenge_required → 尝试下一个因子
    return AuthResult(kind="mfa_required",
                      factors_available=[f.factor_id for f in enrolled])


def try_credential_providers(credentials, *, providers=None, deps=None) -> Optional[ResolvedIdentity]:
    """主认证 provider fallback：按 priority 升序询问已注册 ``ICredentialProvider``，
    首个 ``status="success"`` 经守护式 provisioning 解析/建本地用户。

    返回：
      - ``ResolvedIdentity``：某 provider 认证并成功 provision；
      - ``None``：无 provider 处理（回落到既有路径），或处理了但 provisioning 被护栏拒绝（拒绝登录）。

    安全：单个 provider 抛异常仅记录并跳过（fail-safe，绝不拖垮登录）；provisioning 护栏（C-1/B-4
    等）由 ``resolve_or_create`` 保证。``providers``/``deps`` 可注入以便测试，默认用全局注册表与生产端口。
    """
    from app.core.auth.credentials import CredentialRequest, all_credential_providers
    from app.service.auth.provisioning import default_deps, resolve_or_create

    if providers is None:
        providers = all_credential_providers()
    if not providers:
        return None

    req = CredentialRequest(
        grant_type=getattr(credentials, "grant_type", "password") or "password",
        username=getattr(credentials, "username", None),
        password=getattr(credentials, "password", None),
        code=getattr(credentials, "code", None),
        mfa_code=getattr(credentials, "mfa_code", None),
    )
    deps = deps or default_deps()
    for provider in providers:
        pid = getattr(provider, "provider_id", provider)
        try:
            if not provider.applies_to(req):
                continue
            outcome = provider.verify_credentials(req)
        except Exception as e:  # noqa: BLE001 —— provider 异常一律安全跳过，不拖垮登录
            logger.error(f"主认证提供方 {pid} 校验异常，跳过：{str(e)}")
            continue
        if outcome is None or outcome.status != "success":
            continue
        subject = (outcome.extra or {}).get("subject") or outcome.username
        if not subject:
            logger.warning(f"主认证提供方 {pid} 返回成功但缺少 subject/username，拒绝")
            return None
        user = resolve_or_create(
            getattr(provider, "provider_id", str(pid)),
            subject=str(subject),
            username=outcome.username,
            avatar=outcome.avatar,
            auto_create=bool(getattr(provider, "auto_create", False)),
            deps=deps,
        )
        if user is None:
            logger.warning(f"主认证提供方 {pid} 认证通过，但 provisioning 被护栏拒绝，拒绝登录")
            return None
        return ResolvedIdentity(user=user, apply_mfa=not outcome.mfa_already_satisfied)
    return None
