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
    def begin(self, submission: Any) -> dict:
        """开始一条登录流程（通常携带用户名/口令）。"""
        flow_id = self._store.new_flow_id()
        context = AuthContext(flow_id=flow_id, username=getattr(submission, "username", None))
        cred_flow = self._build_credential_flow()
        context, result = cred_flow.advance(context, submission)
        return self._after_credential(context, result)

    def advance(self, flow_token: str, submission: Any) -> dict:
        """凭流程令牌推进下一步（提交因子码 / 挑战应答 / 后补凭证）。"""
        context = self._store.load(flow_token)
        if context is None:
            return {"status": "failure", "error": "流程不存在或已过期"}

        # 已解析用户：进入 MFA 阶段（先复核用户仍有效，防解析后被禁用）
        if context.resolved_user_id is not None:
            user = self._load_user(context.resolved_user_id)
            if user is None or not getattr(user, "is_active", False):
                self._store.drop(flow_token)
                return {"status": "failure", "error": "用户不存在或已禁用"}
            return self._run_mfa(context, user, submission)

        # 仍在凭证阶段（如分步先取用户名再取口令）
        cred_flow = self._build_credential_flow()
        context, result = cred_flow.advance(context, submission)
        return self._after_credential(context, result)

    # ----------------------------- 阶段编排 -----------------------------
    def _after_credential(self, context: AuthContext, result: Any) -> dict:
        if result.kind == "failure":
            self._store.drop(context.flow_id)
            return {"status": "failure", "error": result.error or "认证失败"}
        if result.kind != "success":
            # 凭证未就绪（缺输入）→ 暂存，提示继续提交凭证
            self._store.save(context)
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
        self._store.save(context)
        return {"status": "mfa_required", "flow_token": context.flow_id,
                "factors_available": [s.step_id for s in enrolled]}

    def _build_credential_flow(self):
        """装配凭证阶段流程，注入 owner 分流端口（resolver + trusted），凭证步外部断言经端口落地。"""
        return build_credential_flow(
            self._credential_steps,
            identity_resolver=self._identity_resolver,
            trusted_step_ids=self._trusted_step_ids)

    def _run_mfa(self, context: AuthContext, user: Any, submission: Any) -> dict:
        factor_steps = self._factor_steps_for(user)
        mfa_flow = build_mfa_flow(factor_steps, requirement=self._mfa_requirement(factor_steps),
                                  identity_resolver=self._identity_resolver,
                                  trusted_step_ids=self._trusted_step_ids)
        context, result = mfa_flow.advance(context, submission)
        if result.kind == "success":
            return self._succeed(context, user)
        if result.kind == "failure":
            self._store.drop(context.flow_id)
            return {"status": "failure", "error": result.error or "二次验证失败"}
        if result.kind == "challenge":
            self._store.save(context)
            return {"status": "challenge", "flow_token": context.flow_id,
                    "challenge": result.challenge, "factors_available": result.factors_available or []}
        # mfa_required：仍需因子输入
        self._store.save(context)
        return {"status": "mfa_required", "flow_token": context.flow_id,
                "factors_available": result.factors_available or []}

    def _mfa_requirement(self, factor_steps: List[Any]) -> AuthRequirement:
        """MFA 组合策略：优先用注入的策略（如 N-of-M），否则默认 ``AnyOf``（复现 v2 OR 语义）。"""
        if self._mfa_requirement_strategy is not None:
            return self._mfa_requirement_strategy(factor_steps)
        return AnyOf([StepRef(s.step_id) for s in factor_steps])

    def _succeed(self, context: AuthContext, user: Any) -> dict:
        self._store.drop(context.flow_id)
        logger.info(f"多步登录流程完成，用户：{getattr(user, 'name', context.resolved_user_id)}")
        return {"status": "success", "token": self._issue_token(user)}
