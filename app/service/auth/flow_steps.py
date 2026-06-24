# -*- coding: utf-8 -*-
"""
流程步骤适配器 —— 把现有认证构件包装成 ``IAuthStep``，供流程引擎驱动（构件级复用，逻辑不重复）。

  - ``FactorStep``            ：包装 ``IMfaFactor``（OTP / PassKey / SMS / 插件因子）；
  - ``CredentialProviderStep``：包装 ``ICredentialProvider``（LDAP/AD/RADIUS/OIDC-ROPC…）+ 守护式 provisioning；
  - ``PasswordStep``          ：本地密码（默认接 UserOper + verify_password，可注入以便测试）。

排序前置由各 ``applies_to`` 声明：凭证步要求"尚未解析用户"，因子步要求"已解析用户且本因子已注册"。
"""
from typing import Any, Callable, List, Optional

from app.core.auth.credentials import CredentialRequest
from app.core.auth.flow import AnyOf, AuthContext, AuthRequirement, AuthStepResult, StepRef
from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
from app.log import logger


def _mfa_ref(ctx: AuthContext) -> MfaUserRef:
    return MfaUserRef(user_id=ctx.resolved_user_id, username=ctx.username or "")


# --------------------------------------------------------------------------- 第二因子


class FactorStep:
    """把一个 ``IMfaFactor`` 适配为流程步骤。``step_id`` 默认取 ``factor_id``，可覆写以支持同类多实例。"""

    step_kind = "factor"

    def __init__(self, factor: Any, step_id: Optional[str] = None) -> None:
        self._factor = factor
        self.step_id = step_id or factor.factor_id
        self.priority = int(getattr(factor, "priority", 0))

    def applies_to(self, context: AuthContext) -> bool:
        if context.resolved_user_id is None:
            return False
        try:
            return bool(self._factor.is_enrolled(_mfa_ref(context)))
        except Exception as e:  # noqa: BLE001 —— 枚举异常视为不可推进，绝不拖垮流程
            logger.error(f"因子 {self.step_id} 注册态判定异常：{str(e)}")
            return False

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        ref = _mfa_ref(context)
        code = getattr(submission, "code", None)
        response = getattr(submission, "response", None)
        # 无任何应答输入：若因子可下发挑战（带外因子）→ 发起挑战；否则等待用户输入
        if not code and not response:
            hint = self._safe_hint(ref)
            if hint is not None and getattr(hint, "challenge", None):
                return AuthStepResult(status="challenge", challenge=hint.challenge)
            return AuthStepResult(status="pending")
        try:
            result = self._factor.verify(ref, MfaSubmission(
                factor_id=getattr(submission, "step_id", None), code=code,
                response=response or {}))
        except Exception as e:  # noqa: BLE001 —— 因子校验异常一律安全失败
            logger.error(f"因子 {self.step_id} 校验异常：{str(e)}")
            return AuthStepResult(status="failed", error="因子校验异常")
        if result.status == "allow":
            return AuthStepResult(status="satisfied")
        if result.status == "deny":
            return AuthStepResult(status="failed", error="因子校验未通过")
        if result.status == "challenge_required":
            return AuthStepResult(status="challenge", challenge=result.challenge)
        return AuthStepResult(status="pending")  # not_enrolled

    def _safe_hint(self, ref: MfaUserRef):
        hint_fn = getattr(self._factor, "challenge_hint", None)
        if not callable(hint_fn):
            return None
        try:
            return hint_fn(ref)
        except Exception as e:  # noqa: BLE001
            logger.error(f"因子 {self.step_id} 下发挑战异常：{str(e)}")
            return None


# --------------------------------------------------------------------------- 主认证 provider


class CredentialProviderStep:
    """把一个 ``ICredentialProvider`` 适配为流程步骤（校验成功后经守护式 provisioning 解析本地用户）。"""

    step_kind = "credential"

    def __init__(self, provider: Any, *, deps: Any = None, step_id: Optional[str] = None) -> None:
        self._provider = provider
        self._deps = deps
        self.step_id = step_id or provider.provider_id
        self.priority = int(getattr(provider, "priority", 0))

    def applies_to(self, context: AuthContext) -> bool:
        return context.resolved_user_id is None

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        req = CredentialRequest(
            grant_type=getattr(submission, "grant_type", "password") or "password",
            username=getattr(submission, "username", None) or context.username,
            password=getattr(submission, "password", None),
            code=getattr(submission, "code", None),
            mfa_code=getattr(submission, "mfa_code", None),
        )
        try:
            if not self._provider.applies_to(req):
                return AuthStepResult(status="pending")
            outcome = self._provider.verify_credentials(req)
        except Exception as e:  # noqa: BLE001 —— provider 异常安全失败（回落下一个步骤）
            logger.error(f"主认证 provider {self.step_id} 校验异常：{str(e)}")
            return AuthStepResult(status="failed", error="provider 校验异常")
        if outcome is None or outcome.status != "success":
            return AuthStepResult(status="failed", error="凭证校验未通过")
        subject = (outcome.extra or {}).get("subject") or outcome.username
        if not subject:
            logger.warning(f"主认证 provider {self.step_id} 成功但缺少 subject，拒绝")
            return AuthStepResult(status="failed", error="缺少身份标识")
        from app.service.auth.provisioning import default_deps, resolve_or_create
        deps = self._deps or default_deps()
        user = resolve_or_create(
            self._provider.provider_id, subject=str(subject), username=outcome.username,
            avatar=outcome.avatar, auto_create=bool(getattr(self._provider, "auto_create", False)),
            deps=deps)
        if user is None:
            return AuthStepResult(status="failed", error="provisioning 被护栏拒绝")
        return AuthStepResult(status="satisfied", user_id=user.id,
                              mfa_satisfied=bool(outcome.mfa_already_satisfied))


# --------------------------------------------------------------------------- 本地密码


class PasswordStep:
    """本地密码步骤（``priority=0``，最先尝试）。``authenticate(username, password) -> user|None`` 可注入。"""

    step_id = "password"
    step_kind = "credential"
    priority = 0

    def __init__(self, authenticate: Optional[Callable[[str, str], Any]] = None) -> None:
        self._authenticate = authenticate or self._default_authenticate

    def applies_to(self, context: AuthContext) -> bool:
        return context.resolved_user_id is None

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        username = getattr(submission, "username", None) or context.username
        password = getattr(submission, "password", None)
        if not username or not password:
            return AuthStepResult(status="pending")
        try:
            user = self._authenticate(username, password)
        except Exception as e:  # noqa: BLE001
            logger.error(f"本地密码校验异常：{str(e)}")
            return AuthStepResult(status="failed", error="密码校验异常")
        if user is None:
            return AuthStepResult(status="failed", error="用户名或密码错误")
        return AuthStepResult(status="satisfied", user_id=user.id)

    @staticmethod
    def _default_authenticate(username: str, password: str) -> Any:
        from app.core.security import verify_password
        from app.db.user_oper import UserOper
        user = UserOper().get_by_name(name=username)
        if not user or not getattr(user, "is_active", False):
            return None
        if not verify_password(password, str(user.hashed_password)):
            return None
        return user


# --------------------------------------------------------------------------- SSO 重定向（统一为 step）


class RedirectStep:
    """把一个 SSO 重定向 ``IAuthProvider`` 统一表示为流程步骤。

    重定向天然无法在单轮内同步完成，故本步推进时下发"跳转 IdP 授权页"的挑战
    （``challenge={kind:"redirect", provider_id, authorize_url}``）；真正的回调换身份/铸票仍走既有
    被验证过的 ``/auth/sso/{id}/callback`` → ticket → ``/auth/exchange`` 路径。如此 SSO 在**流程模型**
    里与密码/因子并列为一种步骤（可放入 ``AnyOf([password, github-sso])`` 等组合），而不重写其机制。

    ``authorize_url_builder(provider) -> url`` 注入（生产侧由端点用 ``begin_login`` + 请求派生 redirect_uri 提供）。
    """

    step_kind = "redirect"

    def __init__(self, provider: Any, *, authorize_url_builder: Optional[Callable[[Any], str]] = None,
                 step_id: Optional[str] = None) -> None:
        self._provider = provider
        self._build_url = authorize_url_builder
        self.step_id = step_id or provider.provider_id
        self.priority = int(getattr(provider, "priority", 100))

    def applies_to(self, context: AuthContext) -> bool:
        return context.resolved_user_id is None

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        url = None
        if self._build_url is not None:
            try:
                url = self._build_url(self._provider)
            except Exception as e:  # noqa: BLE001
                logger.error(f"SSO 步骤 {self.step_id} 构造授权 URL 异常：{str(e)}")
        if not url:
            return AuthStepResult(status="pending")
        return AuthStepResult(status="challenge", challenge={
            "kind": "redirect",
            "provider_id": getattr(self._provider, "provider_id", self.step_id),
            "authorize_url": url,
        })


# --------------------------------------------------------------------------- 流程构建器


def build_credential_flow(steps: List[Any]):
    """构建"任一凭证步骤满足即可"的单阶段流程（password 与各 ICredentialProvider 的 OR 回落）。"""
    from app.service.auth.flow_engine import AuthFlow
    requirement = AnyOf([StepRef(s.step_id) for s in steps])
    return AuthFlow({s.step_id: s for s in steps}, requirement)


def build_mfa_flow(factor_steps: List[Any], requirement: Optional[AuthRequirement] = None):
    """构建第二因子流程；``requirement`` 缺省为 ``AnyOf``（任一因子），可传 ``NOf``/``AllOf`` 实现强 MFA。"""
    from app.service.auth.flow_engine import AuthFlow
    if requirement is None:
        requirement = AnyOf([StepRef(s.step_id) for s in factor_steps])
    return AuthFlow({s.step_id: s for s in factor_steps}, requirement)
