# -*- coding: utf-8 -*-
"""
多步登录服务 —— 用流程引擎驱动"凭证阶段 → 条件 MFA 阶段"，跨请求经 ``FlowStore`` 承载，成功铸 Token。

为何分两阶段而非单条静态流程：MFA 是否必需取决于**已解析用户**的因子注册态（凭证通过后才知道），
故凭证满足后再据用户装配 MFA 子流程——既复现 v2"无因子则免 MFA"语义，又支持 MFA 子流程内任意
组合（AnyOf / NOf 强 MFA）与多轮挑战-应答。引擎与遗留单趟共享同一批步骤/因子/provider 对象。

全部协作经构造注入（FlowStore / 凭证步骤 / 因子装配 / 用户加载 / 铸 Token），本类不直接碰 db。
返回结构化 dict：``{status: success|mfa_required|challenge|continue|failure, ...}``。
"""
from typing import Any, Callable, List, Optional

from app.core.auth.flow import AnyOf, AuthContext, AuthRequirement, StepRef
from app.log import logger
from app.service.auth.flow_steps import build_credential_flow, build_mfa_flow

# --------------------------------------------------------------------------- 模块级工具

_SAFE_REASONS = frozenset({
    "invalid_credentials", "用户名或密码错误", "mfa_required", "invalid_state",
    "invalid_code", "fetch_identity_failed", "user_not_provisioned",
})


def redact_reason(error: str) -> str:
    """白名单脱敏：已知安全的错误代码直通；任何自由文本 / 内部细节脱敏为 auth_failed（仅 debug 记录）。"""
    if error in _SAFE_REASONS:
        return error
    logger.debug("auth 失败原因脱敏：%s", error)
    return "auth_failed"


class _StepTargeted:
    """只读包装：补 ``step_id`` 以把本轮推进定向到指定步骤，其余属性委派内部 submission。

    遵循不可变原则——不就地修改入参；缺失属性经 ``__getattr__`` 透传，由调用方的 ``getattr(.., default)`` 兜底。
    """

    def __init__(self, inner: Any, step_id: str) -> None:
        self._inner = inner
        self.step_id = step_id

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _with_target_step(submission: Any) -> Any:
    """begin 选择器：若 submission 带 ``flow`` 且未显式 ``step_id``，定向到该步骤（如选定某 SSO RedirectStep）。

    引擎本就识别 ``submission.step_id``；此处只补全 step_id，使 ``begin {flow:"<provider>"}`` 直达该步。
    纯密码 begin（无 flow）原样返回，不受影响。
    """
    flow = getattr(submission, "flow", None)
    if not flow or getattr(submission, "step_id", None):
        return submission
    return _StepTargeted(submission, flow)


class FlowService:
    """把流程引擎接成多步登录服务。"""

    def __init__(self, *, flow_store: Any, credential_steps: List[Any],
                 factor_steps_for: Callable[[Any], List[Any]],
                 load_user: Callable[[Any], Optional[Any]],
                 issue_token: Callable[[Any], Any],
                 mfa_requirement: Optional[Callable[[List[Any]], AuthRequirement]] = None,
                 identity_resolver: Optional[Callable[[Any], Optional[Any]]] = None,
                 trusted_step_ids=frozenset({"password"})) -> None:
        self._store = flow_store
        self._credential_steps = list(credential_steps)
        self._factor_steps_for = factor_steps_for
        self._load_user = load_user
        self._issue_token = issue_token
        # MFA 组合策略可注入：缺省 AnyOf（任一因子，复现 v2 OR）；
        # 传 ``lambda steps: NOf(2, [...])`` 即得 N-of-M 强 MFA。插件/配置可据此定制流程形状。
        self._mfa_requirement_strategy = mfa_requirement
        # owner 分流（安全护栏）：仅 ``trusted_step_ids`` 内的内建步可直接携带 user_id；其余凭证步
        # 须交回 ``identity`` 经 ``identity_resolver`` 统一落地。缺省信任内建本地密码步 "password"。
        self._identity_resolver = identity_resolver
        self._trusted_step_ids = frozenset(trusted_step_ids)

    # ----------------------------- 对外入口 -----------------------------
    def run_sync(self, submission: Any) -> dict:
        """单趟同步模式（兼容 /access-token 端点）：把 submission 反复喂给流程直至终态。

        同一 submission 中可同时携带 username/password/otp；引擎每轮推进一个阶段，凭证成功后
        自动进入 MFA（若有），再次喂同一 submission 完成 OTP 校验。重定向挑战无法在单趟内完成，
        会直接返回给调用方处理。无进展保护（避免无限循环）。
        """
        out = self.begin(submission)
        while out.get("status") in ("continue", "mfa_required") and out.get("flow_token"):
            nxt = self.advance(out["flow_token"], submission)
            if nxt == out:  # 无进展（缺输入）→ 停，避免死循环
                break
            out = nxt
        return out  # success / failure / challenge 直接返回

    def begin(self, submission: Any) -> dict:
        """开始一条登录流程（通常携带用户名/口令）。

        携带 ``flow`` 选择器（如 ``{flow:"github"}``）时，把它记入 ``context.requested_step_id``：
        opt-in 类步骤（SSO RedirectStep）仅在被显式选中时才 ``applies_to``，并跨 begin→callback→advance
        经 FlowStore 持久化（``requested_step_id`` 已纳入 to_dict/from_dict）。密码 grant 无 flow →
        requested_step_id 为 None → 任何 RedirectStep 都不参与，密码失败如实收口为失败（而非误转挑战）。
        """
        flow_id = self._store.new_flow_id()
        context = AuthContext(flow_id=flow_id, username=getattr(submission, "username", None),
                              requested_step_id=getattr(submission, "flow", None))
        cred_flow = self._build_credential_flow()
        context, result = cred_flow.advance(context, _with_target_step(submission))
        return self._after_credential(context, result)

    def advance(self, flow_token: str, submission: Any) -> dict:
        """凭流程令牌推进下一步（提交因子码 / 挑战应答 / 后补凭证）。

        使用 CAS (load_versioned + expected_version save) 防止并发丢失更新：
        若两个并发 advance 竞争同一令牌，后提交者的 save 会被 CAS 拒绝，
        返回 operation_conflict 且不 drop 对方写入的状态（另一方的胜出状态保留）。
        """
        context, version = self._store.load_versioned(flow_token)
        if context is None:
            return {"status": "failure", "error": "流程不存在或已过期"}

        # 已解析用户：进入 MFA 阶段（先复核用户仍有效，防解析后被禁用）
        if context.resolved_user_id is not None:
            user = self._load_user(context.resolved_user_id)
            if user is None or not getattr(user, "is_active", False):
                self._store.drop(flow_token)
                return {"status": "failure", "error": "用户不存在或已禁用"}
            return self._run_mfa(context, user, submission, expected_version=version)

        # 仍在凭证阶段（如分步先取用户名再取口令）
        cred_flow = self._build_credential_flow()
        context, result = cred_flow.advance(context, submission)
        return self._after_credential(context, result, expected_version=version)

    # ----------------------------- CAS 辅助 -----------------------------
    def _save_cas(self, context: AuthContext, expected_version: Optional[int]) -> bool:
        """CAS 写入：返回 True 表示成功，False 表示版本冲突（另一并发方已提交）。"""
        ok, _ = self._store.save(context, expected_version=expected_version)
        return ok

    # ----------------------------- 阶段编排 -----------------------------
    def _after_credential(self, context: AuthContext, result: Any,
                          expected_version: Optional[int] = None) -> dict:
        if result.kind == "failure":
            self._store.drop(context.flow_id)
            return {"status": "failure", "error": result.error or "认证失败"}
        if result.kind == "challenge":
            # SSO/重定向步发起挑战（如 RedirectChallenge）→ 下发 authorize_url，暂存流程状态
            if not self._save_cas(context, expected_version):
                return {"status": "failure", "error": "operation_conflict"}
            return {"status": "challenge", "flow_token": context.flow_id,
                    "challenge": result.challenge, "factors_available": result.factors_available or []}
        if result.kind != "success":
            # 凭证未就绪（缺输入）→ 暂存，提示继续提交凭证
            if not self._save_cas(context, expected_version):
                return {"status": "failure", "error": "operation_conflict"}
            return {"status": "continue", "flow_token": context.flow_id,
                    "steps_available": result.factors_available or []}

        user = self._load_user(context.resolved_user_id)
        if user is None or not getattr(user, "is_active", False):
            self._store.drop(context.flow_id)
            return {"status": "failure", "error": "用户不存在或已禁用"}

        # 联合方已断言 MFA 满足 → 直接成功
        if context.mfa_satisfied:
            return self._succeed(context, user)

        # 条件 MFA：据已解析用户装配因子；无已注册因子 → 免 MFA 直接成功
        enrolled = [s for s in self._factor_steps_for(user) if s.applies_to(context)]
        if not enrolled:
            return self._succeed(context, user)
        if not self._save_cas(context, expected_version):
            return {"status": "failure", "error": "operation_conflict"}
        return {"status": "mfa_required", "flow_token": context.flow_id,
                "factors_available": [s.step_id for s in enrolled]}

    def _build_credential_flow(self):
        """装配凭证阶段流程，注入 owner 分流端口（resolver + trusted），凭证步外部断言经端口落地。"""
        return build_credential_flow(
            self._credential_steps,
            identity_resolver=self._identity_resolver,
            trusted_step_ids=self._trusted_step_ids)

    def _run_mfa(self, context: AuthContext, user: Any, submission: Any,
                 expected_version: Optional[int] = None) -> dict:
        # 仅取当前可推进的已注册因子（enrolled 子集为唯一事实来源，避免恒假叶子污染 candidates）
        factor_steps = [s for s in self._factor_steps_for(user) if s.applies_to(context)]
        requirement = self._validate_requirement(self._mfa_requirement(factor_steps), factor_steps)
        # MFA 阶段无受信凭证步 → trusted 传空集（防 "password" 泄漏进 MFA 阶段）
        mfa_flow = build_mfa_flow(factor_steps, requirement=requirement,
                                  identity_resolver=self._identity_resolver,
                                  trusted_step_ids=frozenset())
        context, result = mfa_flow.advance(context, submission)
        if result.kind == "success":
            return self._succeed(context, user)
        if result.kind == "failure":
            self._store.drop(context.flow_id)
            return {"status": "failure", "error": result.error or "二次验证失败"}
        if result.kind == "challenge":
            if not self._save_cas(context, expected_version):
                return {"status": "failure", "error": "operation_conflict"}
            return {"status": "challenge", "flow_token": context.flow_id,
                    "challenge": result.challenge, "factors_available": result.factors_available or []}
        # mfa_required：仍需因子输入
        if not self._save_cas(context, expected_version):
            return {"status": "failure", "error": "operation_conflict"}
        return {"status": "mfa_required", "flow_token": context.flow_id,
                "factors_available": result.factors_available or []}

    def _validate_requirement(self, requirement: AuthRequirement, steps: List[Any]) -> AuthRequirement:
        """校验 MFA requirement 合法性；两类降级为 AnyOf，防止绕过或死锁：

        1. 空真（empty-true）：requirement 对空 satisfied 集即满足（如 AllOf([]) / NOf(0)）→
           降级为 AnyOf([enrolled steps])，强制至少完成一个因子。
        2. NOf.n 超过可满足叶子数 → 永不可满足（确定性死锁）→ 同样降级为 AnyOf。

        若 steps 为空，AnyOf([]) 对空集仍为 False（任一…不成立），流程引擎的死局分支返回 failure，
        比无限 mfa_required 更安全。
        """
        try:
            if requirement.is_satisfied(frozenset()):
                logger.warning("MFA requirement 对空集即满足（空真），降级为 AnyOf 防绕过")
                return AnyOf([StepRef(s.step_id) for s in steps])
        except Exception:  # noqa: BLE001
            pass
        n = getattr(requirement, "n", None)
        if isinstance(n, int) and not isinstance(n, bool) and n > len(steps):
            logger.warning("MFA NOf.n(%s) > 可满足因子数(%s)，降级为 AnyOf", n, len(steps))
            return AnyOf([StepRef(s.step_id) for s in steps])
        return requirement

    def _mfa_requirement(self, factor_steps: List[Any]) -> AuthRequirement:
        """MFA 组合策略：优先用注入的策略（如 N-of-M），否则默认 ``AnyOf``（复现 v2 OR 语义）。"""
        if self._mfa_requirement_strategy is not None:
            return self._mfa_requirement_strategy(factor_steps)
        return AnyOf([StepRef(s.step_id) for s in factor_steps])

    def _succeed(self, context: AuthContext, user: Any) -> dict:
        self._store.drop(context.flow_id)
        logger.info(f"多步登录流程完成，用户：{getattr(user, 'name', context.resolved_user_id)}")
        return {"status": "success", "token": self._issue_token(user)}
