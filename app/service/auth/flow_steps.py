# -*- coding: utf-8 -*-
"""
流程步骤适配器 —— 把现有认证构件包装成 ``IAuthStep``，供流程引擎驱动（构件级复用，逻辑不重复）。

  - ``FactorStep``            ：包装一个 MFA 因子构件（OTP / PassKey / SMS / 插件因子，鸭子类型）；
  - ``CredentialProviderStep``：包装一个主认证 provider 构件（LDAP/AD/RADIUS/OIDC-ROPC…，鸭子类型）+ 守护式 provisioning；
  - ``PasswordStep``          ：本地密码（默认接 UserOper + verify_password，可注入以便测试）。

排序前置由各 ``applies_to`` 声明：凭证步要求"尚未解析用户"，因子步要求"已解析用户且本因子已注册"。
"""
from typing import Any, Callable, Dict, List, Optional

from app.core.auth.challenge import PromptChallenge, RedirectChallenge
from app.core.auth.flow import (
    AnyOf,
    AuthContext,
    AuthRequirement,
    AuthStepResult,
    IdentityAssertion,
    StepRef,
)
from app.core.auth.types import CredentialRequest, MfaSubmission, MfaUserRef
from app.log import logger
# 模块级导入：测试经 monkeypatch app.service.auth.flow_steps.resolve_or_create 注入测试缝；
# provisioning 不反向导入 flow_steps，故无环（已核验）。
from app.service.auth.provisioning import resolve_or_create


def _mfa_ref(ctx: AuthContext) -> MfaUserRef:
    return MfaUserRef(user_id=ctx.resolved_user_id, username=ctx.username or "")


# --------------------------------------------------------------------------- 第二因子


class FactorStep:
    """把一个 MFA 因子构件适配为流程步骤。``step_id`` 默认取 ``factor_id``，可覆写以支持同类多实例。"""

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
            if hint is not None:
                if getattr(hint, "challenge", None):
                    return AuthStepResult(status="challenge", challenge=hint.challenge)
                # 因子已注册但无带外挑战（TOTP/OTP）→ 提示用户输入动态码
                return AuthStepResult(
                    status="challenge",
                    challenge=PromptChallenge(step_id=self.step_id, prompt="请输入动态码", input_kind="otp"),
                )
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
    """把一个主认证 provider 构件适配为流程步骤（校验成功后经守护式 provisioning 解析本地用户）。"""

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
        # 不在步骤内解析；交回身份断言，由引擎注入端口 resolve_or_create 统一落地（C-1/B-4 单一来源）
        return AuthStepResult(status="satisfied", identity=IdentityAssertion(
            provider_id=self._provider.provider_id,
            subject=str(subject),
            username=outcome.username,
            avatar=outcome.avatar,
            auto_create=bool(getattr(self._provider, "auto_create", False)),
            mfa_already_satisfied=bool(outcome.mfa_already_satisfied)))


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


# --------------------------------------------------------------------------- 媒体服务器辅助认证


class AuxiliaryCredentialStep:
    """把 ``UserChain.auxiliary_authenticate``（媒体服务器 ``user_authenticate`` 模块 + AuthVerification
    事件）适配为内建凭证步骤，恢复 ``AUXILIARY_AUTH_ENABLE`` 用户经媒体服务器登录的能力。

    排在本地密码（priority 0）之后（priority 50）：本地密码失败（如用户非本地）→ 引擎 AnyOf 回落到本步，
    用同一份用户名/口令尝试媒体服务器辅助认证。

    **受信内建步**：直接返回 ``user_id``（其建号经 ``_process_auth_success`` 走媒体服务器专属逻辑，
    而非统一的 ``resolve_or_create`` 护栏），故须由装配桥纳入 ``trusted_step_ids`` 方能被引擎接受。
    任何异常一律捕获并安全失败，绝不拖垮流程。
    """

    step_id = "auxiliary"
    step_kind = "credential"
    priority = 50

    def __init__(self, authenticate: Optional[Callable[[Any], Any]] = None) -> None:
        # authenticate(credentials) -> (ok: bool, user_or_msg)；缺省接 UserChain().auxiliary_authenticate。
        self._authenticate = authenticate

    def applies_to(self, context: AuthContext) -> bool:
        from app.core.config import settings
        return context.resolved_user_id is None and bool(settings.AUXILIARY_AUTH_ENABLE)

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        from app.schemas import AuthCredentials
        username = getattr(submission, "username", None) or context.username
        try:
            credentials = AuthCredentials(
                grant_type=getattr(submission, "grant_type", "password") or "password",
                username=username,
                password=getattr(submission, "password", None),
                code=getattr(submission, "code", None),
                mfa_code=getattr(submission, "mfa_code", None),
                token=getattr(submission, "token", None),
                channel=getattr(submission, "channel", None),
                service=getattr(submission, "service", None),
            )
            authenticate = self._authenticate or self._default_authenticate
            ok, result = authenticate(credentials)
        except Exception as e:  # noqa: BLE001 —— 辅助认证异常一律捕获并安全失败
            logger.error(f"辅助认证步骤异常：{str(e)}")
            return AuthStepResult(status="failed", error="辅助认证异常")
        if not ok:
            return AuthStepResult(status="failed", error="辅助认证未通过")
        user_id = getattr(result, "id", None)
        if user_id is None:
            logger.warning("辅助认证成功但缺少用户 id，拒绝")
            return AuthStepResult(status="failed", error="辅助认证未通过")
        # 受信内建步：直接落 user_id（其 provisioning 为媒体服务器专属，非 resolve_or_create）
        return AuthStepResult(status="satisfied", user_id=user_id)

    @staticmethod
    def _default_authenticate(credentials: Any) -> Any:
        from app.chain.user import UserChain
        return UserChain().auxiliary_authenticate(credentials)


# --------------------------------------------------------------------------- SSO 重定向（统一为 step）


def _default_consume_state(state: Optional[str]) -> Optional[Dict[str, Any]]:
    """默认 CSRF state 消费（取即销毁）：接 ``app.core.auth.redirect`` 的单例 state 存储；
    返回载荷 dict（``{flow_token, provider_id}``）或 None。"""
    from app.core.auth.redirect import consume_state
    return consume_state(state)


def _default_issue_state(flow_token: str, provider_id: str) -> str:
    """默认 CSRF state 签发：接 ``app.core.auth.redirect`` 的单例 state 存储，绑定 flow_token + provider_id。"""
    from app.core.auth.redirect import issue_state
    return issue_state(flow_token=flow_token, provider_id=provider_id)


def _default_flow_redirect_uri() -> str:
    """默认统一流程 SSO 回调 redirect_uri：``/api/v1/auth/flow/callback`` 的绝对 URL（优先 APP_DOMAIN）。

    生产侧端点会注入与请求 Host 一致的 builder（见 ``auth._flow_callback_uri``）以保证签发/回调一致；
    本默认仅作未注入时的兜底（APP_DOMAIN 已配则为绝对 URL）。"""
    from app.core.config import settings
    return settings.MP_DOMAIN("/api/v1/auth/flow/callback") or "/api/v1/auth/flow/callback"


class RedirectStep:
    """把一个 SSO 重定向 ``IAuthProvider`` 表示为**完整的双模流程步骤**：

    - **无授权码**（首次被选中）：下发"跳转 IdP 授权页"的挑战
      （``challenge={kind:"redirect", provider_id, authorize_url}``），由前端 302 用户至 IdP；
    - **带授权码**（IdP 回调后由端点回灌的应答）：校验 CSRF ``state`` → ``fetch_identity`` 换外部身份
      → 守护式 ``resolve_or_create`` 解析/建本地用户 → ``satisfied(user_id)``。

    如此 SSO 与密码/因子一样**完整经流程引擎驱动**（不再走 ticket/exchange 旁路），从而自动获得条件
    MFA 与任意组合（``AnyOf([password, github])`` 等）。CSRF / 换身份 / 护栏失败均返回 ``failed``。

    协作可注入以便单测：``issue_state(flow_token, provider_id)->str``（统一流程签发 flow 绑定 state）、
    ``consume_state(state)->payload|None``、``redirect_uri``（``/auth/flow/callback`` 的绝对 URL，str 或
    无参 builder）、provisioning ``deps``（生产侧缺省接单例 state 存储 / ``default_deps`` / APP_DOMAIN）。

    ``authorize_url_builder(provider)->url`` 为可选注入：传入时直接用它构造授权 URL（不签发 state）；
    不传时（默认）由 ``provider.authorize_url(state, redirect_uri)`` 自签 flow 绑定的 state。
    """

    step_kind = "redirect"

    def __init__(self, provider: Any, *, authorize_url_builder: Optional[Callable[[Any], str]] = None,
                 consume_state: Optional[Callable[[Optional[str]], Optional[Dict[str, Any]]]] = None,
                 issue_state: Optional[Callable[[str, str], str]] = None,
                 redirect_uri: Any = None,
                 deps: Any = None, step_id: Optional[str] = None) -> None:
        self._provider = provider
        self._build_url = authorize_url_builder
        self._consume_state = consume_state
        self._issue_state = issue_state or _default_issue_state
        self._redirect_uri = redirect_uri if redirect_uri is not None else _default_flow_redirect_uri
        self._deps = deps
        self.step_id = step_id or provider.provider_id
        self.priority = int(getattr(provider, "priority", 100))

    def applies_to(self, context: AuthContext) -> bool:
        # **opt-in**：仅当流程显式选中本重定向步（``requested_step_id == step_id``）时才参与。
        # 否则密码 grant 的 OR 回落会在密码失败后误触 RedirectStep 下发跳转挑战，把"密码错误"伪装成
        # "需 MFA/重定向"（暴力破解不可见）。凭证类步（Password/CredentialProvider）保持自动回落不受影响。
        return context.resolved_user_id is None and context.requested_step_id == self.step_id

    def advance(self, context: AuthContext, submission: Any) -> AuthStepResult:
        code = getattr(submission, "code", None)
        if not code:
            # 回调上下文（带 state / state_payload 却无 code）= IdP 拒绝/取消（?error=...，无 code）：
            # 快速失败，不再调用 _issue_redirect 铸新的孤儿 state。
            # 纯发起态（无 state、无 code）才下发跳转挑战，等待 IdP 回调。
            if getattr(submission, "state", None) or getattr(submission, "state_payload", None):
                return AuthStepResult(status="failed", error="invalid_code")
            return self._issue_redirect(context)
        # 带授权码：完成回调认证（CSRF → 换身份 → 交回身份断言）
        return self._complete_callback(context, submission, code)

    def _issue_redirect(self, context: AuthContext) -> AuthStepResult:
        provider_id = getattr(self._provider, "provider_id", self.step_id)
        if self._build_url is not None:
            # 注入了 URL 构造器时：直接用它构造授权 URL，不签发 state
            try:
                url = self._build_url(self._provider)
            except Exception as e:  # noqa: BLE001
                logger.error(f"SSO 步骤 {self.step_id} 构造授权 URL 异常：{str(e)}")
                return AuthStepResult(status="pending")
        else:
            # 统一流程：签发与本 flow + provider 绑定的一次性 state，再由 provider 构造授权 URL
            try:
                state = self._issue_state(flow_token=context.flow_id, provider_id=provider_id)
                redirect_uri = self._redirect_uri() if callable(self._redirect_uri) else self._redirect_uri
                url = self._provider.authorize_url(state, redirect_uri)
            except Exception as e:  # noqa: BLE001
                logger.error(f"SSO 步骤 {self.step_id} 签发 state / 构造授权 URL 异常：{str(e)}")
                return AuthStepResult(status="pending")
        if not url:
            return AuthStepResult(status="pending")
        return AuthStepResult(status="challenge", challenge=RedirectChallenge(
            step_id=self.step_id, provider_id=provider_id, authorize_url=url))

    def _complete_callback(self, context: AuthContext, submission: Any, code: str) -> AuthStepResult:
        from app.core.auth.identifiers import is_valid_code
        # 1) CSRF：state 必须本服务签发、未过期、未用过（取即销毁），返回载荷 dict 或 None。
        #    薄桥（/auth/flow/callback）已消费一次 state 取回 flow_token，故经 ``state_payload`` 透传预消费
        #    载荷——本步不再二次消费（保证 consume-once）；无 state_payload 时回落到直接 consume。
        consume = self._consume_state or _default_consume_state
        payload = getattr(submission, "state_payload", None) or consume(getattr(submission, "state", None))
        if not payload:
            logger.warning(f"SSO 步骤 {self.step_id} 回调 state 校验失败（CSRF 或已过期）")
            return AuthStepResult(status="failed", error="invalid_state")
        # 跨 provider / 跨 flow 绑定校验（spec §4.7）
        if payload.get("provider_id") != getattr(self._provider, "provider_id", self.step_id):
            return AuthStepResult(status="failed", error="invalid_state")
        if payload.get("flow_token") not in (None, "", context.flow_id):
            return AuthStepResult(status="failed", error="invalid_state")
        # 2) 边界校验授权码
        if not is_valid_code(code):
            return AuthStepResult(status="failed", error="invalid_code")
        # 3) 换取外部身份（提供方异常一律安全失败）
        redirect_uri = getattr(submission, "redirect_uri", None)
        try:
            identity = self._provider.fetch_identity(code, redirect_uri)
        except Exception as e:  # noqa: BLE001
            logger.error(f"SSO 步骤 {self.step_id} 换取身份异常：{str(e)}")
            return AuthStepResult(status="failed", error="fetch_identity_failed")
        if not identity or not getattr(identity, "username", None):
            return AuthStepResult(status="failed", error="fetch_identity_failed")
        # 4) 不在步骤内解析；交回身份断言，由引擎注入端口 resolve_or_create 统一落地（C-1/B-4 单一来源）
        return AuthStepResult(status="satisfied", identity=IdentityAssertion(
            provider_id=self._provider.provider_id,
            subject=(getattr(identity, "subject", "") or ""),
            username=getattr(identity, "username", None),
            avatar=getattr(identity, "avatar", None),
            auto_create=bool(getattr(self._provider, "auto_create", False))))


# --------------------------------------------------------------------------- 身份解析端口


def make_identity_resolver(deps):
    """把 ``IdentityAssertion`` 经守护式 ``resolve_or_create``（C-1/B-4 护栏单一来源）解析为本地 user_id。

    供流程引擎在外部断言落地时注入（owner 分流：仅受信内建步可直接携带 user_id，其余须经此端口）。
    使用模块级 ``resolve_or_create`` 以保留测试缝（monkeypatch 本模块同名符号）。
    """
    def _resolve(assertion):
        user = resolve_or_create(
            assertion.provider_id, subject=assertion.subject, username=assertion.username,
            avatar=assertion.avatar, auto_create=assertion.auto_create, deps=deps)
        return user.id if user else None
    return _resolve


# --------------------------------------------------------------------------- 流程构建器


def build_credential_flow(steps: List[Any], *, identity_resolver=None, trusted_step_ids=frozenset()):
    """构建"任一凭证步骤满足即可"的单阶段流程（password 与各外部直验凭证步的 OR 回落）。

    ``identity_resolver`` / ``trusted_step_ids`` 由上层（FlowService / 端点）注入：内建受信步可直接落
    user_id，外部凭证步交回 ``identity`` 经端口解析（owner 分流的单一落地点）。"""
    from app.service.auth.flow_engine import AuthFlow
    requirement = AnyOf([StepRef(s.step_id) for s in steps])
    return AuthFlow({s.step_id: s for s in steps}, requirement,
                    identity_resolver=identity_resolver, trusted_step_ids=trusted_step_ids)


def build_mfa_flow(factor_steps: List[Any], requirement: Optional[AuthRequirement] = None,
                   *, identity_resolver=None, trusted_step_ids=frozenset()):
    """构建第二因子流程；``requirement`` 缺省为 ``AnyOf``（任一因子），可传 ``NOf``/``AllOf`` 实现强 MFA。"""
    from app.service.auth.flow_engine import AuthFlow
    if requirement is None:
        requirement = AnyOf([StepRef(s.step_id) for s in factor_steps])
    return AuthFlow({s.step_id: s for s in factor_steps}, requirement,
                    identity_resolver=identity_resolver, trusted_step_ids=trusted_step_ids)
