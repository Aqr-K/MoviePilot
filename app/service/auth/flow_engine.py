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
from app.log import logger


class AuthFlow:
    """一条可推进的认证流程：步骤集合 + 组合策略。

    可选关键字参数（Task 10 起由 builder 统一注入，遗留调用方无需传递）：
      - ``identity_resolver``  : 外部身份断言 → uid 的映射函数；None = 遗留/内建模式。
      - ``trusted_step_ids``   : 允许直接携带 user_id 的内建步骤白名单；其余步骤须经 identity 端口。
      - ``max_attempts``       : 单流程最大推进轮数，超限返回 failure（默认 10）。
    """

    def __init__(
        self,
        steps: Dict[str, Any],
        requirement: AuthRequirement,
        *,
        identity_resolver=None,
        trusted_step_ids=frozenset(),
        max_attempts: int = 10,
    ) -> None:
        self.steps = dict(steps)
        self.requirement = requirement
        self._resolve_identity = identity_resolver
        self._trusted = frozenset(trusted_step_ids)
        self._max_attempts = int(max_attempts)

    def _actionable(self, ctx: AuthContext) -> list:
        """当前可推进的步骤：策略候选 ∩ 已注册 ∩ ``applies_to`` 为真，按 priority 升序。"""
        cand = self.requirement.candidates(set(ctx.satisfied_steps))
        steps = [self.steps[s] for s in cand
                 if s in self.steps and self.steps[s].applies_to(ctx)]
        return sorted(steps, key=lambda s: getattr(s, "priority", 0))

    def _accept_satisfied(self, ctx: AuthContext, step: Any, res: Any) -> Optional[AuthContext]:
        """满足后的身份落地：受信内建步或遗留模式直接取 user_id；外部断言经 identity 端口。

        返回 None 表示护栏拒绝（非受信步给出 user_id 且已配 resolver）。
        """
        # 受信内建步，或未配置 owner 分流（identity_resolver 缺省 = 遗留模式）→ 接受 user_id
        if res.user_id is not None and (step.step_id in self._trusted or self._resolve_identity is None):
            return ctx.with_satisfied(step.step_id).with_resolved_user(
                res.user_id, mfa_satisfied=res.mfa_satisfied or ctx.mfa_satisfied)
        # 外部身份断言 → 经注入端口落地（单一来源）
        if res.identity is not None and self._resolve_identity is not None:
            uid = self._resolve_identity(res.identity)
            if uid is None:
                return None
            return ctx.with_satisfied(step.step_id).with_resolved_user(
                uid, mfa_satisfied=res.identity.mfa_already_satisfied or ctx.mfa_satisfied)
        # satisfied 但无身份（如因子步仅标记满足）
        if res.user_id is None and res.identity is None:
            c = ctx.with_satisfied(step.step_id)
            if res.mfa_satisfied and c.resolved_user_id is not None:
                c = c.with_resolved_user(c.resolved_user_id, mfa_satisfied=True)
            return c
        # 非受信步给 user_id 且已配 resolver、又无 identity → 护栏拒绝
        return None

    def advance(self, ctx: AuthContext, submission: Any = None) -> Tuple[AuthContext, AuthResult]:
        """推进一轮，返回 (新状态, 类型化结果)。"""
        ctx = ctx.with_attempt()
        if self.requirement.is_satisfied(set(ctx.satisfied_steps)):
            return ctx, AuthResult(kind="success")
        if ctx.attempts > self._max_attempts:
            return ctx, AuthResult(kind="failure", error="认证尝试次数超限")

        target = getattr(submission, "step_id", None) if submission is not None else None
        todo = self._actionable(ctx)
        if target:
            todo = [s for s in todo if s.step_id == target]

        acted = False
        any_failed = False
        last_err: Optional[str] = None
        for step in todo:
            try:
                res = step.advance(ctx, submission)
            except Exception as exc:  # noqa: BLE001
                logger.error("AuthFlow: step %r raised unexpectedly — treating as failed: %s", step.step_id, exc)
                any_failed = True
                last_err = f"认证步骤内部错误: {exc}"
                continue
            if res.status == "satisfied":
                nc = self._accept_satisfied(ctx, step, res)
                if nc is None:
                    any_failed = True
                    last_err = "认证步骤被护栏拒绝"
                    continue
                ctx = nc
                acted = True
                break
            if res.status == "challenge":
                # hasattr 守卫：过渡兼容 T8 前步骤直接返回 dict challenge（T13 去守卫）
                payload = res.challenge.to_dict() if hasattr(res.challenge, "to_dict") else (res.challenge or {})
                ctx = ctx.with_challenge(step.step_id, payload)
                return ctx, AuthResult(kind="challenge", challenge=payload or None,
                                       factors_available=[s.step_id for s in self._actionable(ctx)])
            if res.status == "failed":
                any_failed = True
                last_err = res.error or "认证失败"
                continue
            # pending → 尝试下一个可推进步骤

        if self.requirement.is_satisfied(set(ctx.satisfied_steps)):
            return ctx, AuthResult(kind="success")

        rem = [s.step_id for s in self._actionable(ctx)]
        if acted and rem:
            # 本轮有进展但流程未完成 → 还需后续步骤输入
            return ctx, AuthResult(kind="mfa_required", factors_available=rem)
        if not rem:
            # 无可推进步骤（死局 / 前置未满足）→ failure
            return ctx, AuthResult(kind="failure", error=last_err or "所需认证步骤不可用")
        if any_failed:
            # 本轮所试步骤全部明确失败 → 认证失败
            return ctx, AuthResult(kind="failure", error=last_err)
        return ctx, AuthResult(kind="mfa_required", factors_available=rem)


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
