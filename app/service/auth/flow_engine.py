# -*- coding: utf-8 -*-
"""
认证流程引擎 —— 按组合策略路由步骤、单轮推进，并用 ``FlowStore`` 跨请求承载多步/多轮状态。

``AuthFlow.advance(context, submission)`` 处理**一轮**推进：

  1. 若策略已满足 → ``success``；
  2. 否则取"候选且 ``applies_to`` 为真"的步骤（按 priority 升序）；若提交指定了 ``step_id`` 则只推进该步；
  3. 依次推进，遇 ``satisfied`` 即记入已满足并重判策略（凭证 OR 回落：前一个失败则试下一个）；
     遇 ``challenge`` 即下发挑战返回；全部 ``failed`` 且无进展 → ``failure``；仅缺输入 → ``mfa_required``。

引擎本身 db-free：成功身份以 ``context.resolved_user_id`` 承载，由上层（端点/服务）据此加载 ``User``。
"""
import secrets
from typing import Any, Dict, Optional, Tuple

from app.core.auth.flow import AuthContext, AuthRequirement
from app.core.auth.outcome import AuthResult
from app.core.challenge_store import ChallengeStore


class AuthFlow:
    """一条可推进的认证流程：步骤集合 + 组合策略。"""

    def __init__(self, steps: Dict[str, Any], requirement: AuthRequirement) -> None:
        self.steps = dict(steps)
        self.requirement = requirement

    def _actionable(self, context: AuthContext) -> list:
        """当前可推进的步骤：策略候选 ∩ 已注册 ∩ ``applies_to`` 为真，按 priority 升序。"""
        sat = set(context.satisfied_steps)
        candidates = self.requirement.candidates(sat)
        steps = [self.steps[s] for s in candidates
                 if s in self.steps and self.steps[s].applies_to(context)]
        return sorted(steps, key=lambda s: getattr(s, "priority", 0))

    def advance(self, context: AuthContext, submission: Any = None) -> Tuple[AuthContext, AuthResult]:
        """推进一轮，返回 (新状态, 类型化结果)。"""
        context = context.with_attempt()
        if self.requirement.is_satisfied(set(context.satisfied_steps)):
            return context, AuthResult(kind="success")

        target_id = getattr(submission, "step_id", None) if submission is not None else None
        steps_to_try = self._actionable(context)
        if target_id:
            steps_to_try = [s for s in steps_to_try if s.step_id == target_id]

        acted = False
        any_failed = False
        last_error: Optional[str] = None
        for step in steps_to_try:
            result = step.advance(context, submission)
            if result.status == "satisfied":
                context = context.with_satisfied(step.step_id)
                if result.user_id is not None:
                    context = context.with_resolved_user(
                        result.user_id, mfa_satisfied=result.mfa_satisfied or context.mfa_satisfied)
                elif result.mfa_satisfied and context.resolved_user_id is not None:
                    context = context.with_resolved_user(context.resolved_user_id, mfa_satisfied=True)
                acted = True
                break
            if result.status == "challenge":
                context = context.with_challenge(step.step_id, result.challenge or {})
                remaining = sorted(self.requirement.candidates(set(context.satisfied_steps)))
                return context, AuthResult(kind="challenge", challenge=result.challenge,
                                           factors_available=remaining)
            if result.status == "failed":
                any_failed = True
                last_error = result.error or "认证失败"
                continue
            # pending → 尝试下一个可推进步骤

        satisfied = set(context.satisfied_steps)
        if self.requirement.is_satisfied(satisfied):
            return context, AuthResult(kind="success")

        remaining = sorted(self.requirement.candidates(satisfied))
        if acted:
            # 本轮有进展（某步满足）但流程未完成 → 还需后续步骤输入
            return context, AuthResult(kind="mfa_required", factors_available=remaining)
        if any_failed:
            # 本轮所试步骤全部明确失败、无进展 → 认证失败
            return context, AuthResult(kind="failure", error=last_error)
        if remaining:
            # 仅缺输入（步骤适用但本轮未提交）→ 提示需要后续步骤
            return context, AuthResult(kind="mfa_required", factors_available=remaining)
        return context, AuthResult(kind="failure", error="无可用认证步骤")


class FlowStore:
    """跨请求承载流程状态：内存 + TTL（建在 ``ChallengeStore`` 上）。

    多步/多轮流程**非单次**：``load`` 不消费，每轮推进后用同一 ``flow_id`` 重新 ``save`` 覆盖。
    进程内存足矣（重启失效 = 重新登录，可接受），不碰 db、不动 ``security.py``。
    """

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._store = ChallengeStore(ttl_seconds=ttl_seconds)

    @staticmethod
    def new_flow_id() -> str:
        """生成不可猜测的流程令牌（前端持有，跨轮回传）。"""
        return secrets.token_urlsafe(24)

    def save(self, context: AuthContext) -> str:
        """保存/覆盖流程状态，返回其 ``flow_id``（即令牌）。"""
        self._store.put(context.flow_id, context.to_dict())
        return context.flow_id

    def load(self, flow_id: str) -> Optional[AuthContext]:
        """按令牌取回流程状态（不消费）；不存在/过期返回 None。"""
        data = self._store.get(flow_id)
        return AuthContext.from_dict(data) if data else None

    def drop(self, flow_id: str) -> None:
        """流程完成/失败后主动清除状态。"""
        self._store.delete(flow_id)
