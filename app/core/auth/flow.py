# -*- coding: utf-8 -*-
"""
认证流程状态机核心（db-free）。

把"认证"建模为可任意组合、任意排序、任意轮数的**多步流程**：

  - ``IAuthStep``       ：一个可推进的认证步骤（凭证校验 / 第二因子 / 重定向 …），统一最小契约；
  - ``AuthStepResult``  ：单步推进的类型化结果（satisfied / failed / challenge / pending）；
  - ``AuthRequirement`` ：组合策略树（``StepRef`` / ``AllOf`` / ``AnyOf`` / ``NOf``），声明"需要哪些步骤
    被满足才算认证完成"——AND / OR / N-of-M 任意嵌套；
  - ``AuthContext``     ：跨请求的不可变流程状态（已满足步骤、已解析用户、挑战、尝试次数…），
    可 JSON 序列化以便 ``FlowStore`` 在多步/多轮之间承载。

排序无需在策略树里硬编码：每个步骤的 ``applies_to(context)`` 自行声明其前置条件（如第二因子要求
``resolved_user_id`` 已就绪），故"先凭证后因子"等顺序由前置门控自然涌现，引擎只按候选 + priority 路由。
"""
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Protocol, Set, runtime_checkable

# --------------------------------------------------------------------------- 单步结果


@dataclass(frozen=True)
class AuthStepResult:
    """单个步骤一次推进的结果。``status`` 语义：

    - ``"satisfied"``：本步完成（凭证步可同时经 ``user_id`` 解析出身份）；
    - ``"failed"``   ：本步明确失败（如密码错、因子拒绝）——整条流程失败；
    - ``"challenge"``：需先下发挑战 / 用户带外应答（SMS、重定向等），``challenge`` 为前端提示载荷；
    - ``"pending"``  ：本步适用但本轮缺少输入，需用户提交后再推进。
    """

    status: str
    user_id: Optional[Any] = None
    mfa_satisfied: bool = False
    challenge: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------- 步骤契约


@runtime_checkable
class IAuthStep(Protocol):
    """认证步骤契约（凭证 provider / MFA 因子 / SSO 重定向 等都适配为此）。

    数据属性：``step_id``（唯一）、``step_kind``（credential / factor / redirect …）、``priority``（升序路由）。
    方法：
      - ``applies_to(context)``           ：在当前流程状态下本步是否可推进（声明前置条件，决定排序）；
      - ``advance(context, submission)``  ：用本轮提交推进本步，返回 ``AuthStepResult``（永不抛异常）。
    """

    step_id: str
    step_kind: str
    priority: int

    def applies_to(self, context: "AuthContext") -> bool: ...

    def advance(self, context: "AuthContext", submission: Any) -> AuthStepResult: ...


# --------------------------------------------------------------------------- 组合策略


class AuthRequirement:
    """组合策略基类：声明"哪些步骤被满足才算流程完成"。"""

    def is_satisfied(self, satisfied: Set[str]) -> bool:
        raise NotImplementedError

    def candidates(self, satisfied: Set[str]) -> Set[str]:
        """仍可能对"满足"有贡献、且尚未满足的叶子步骤集合（已满足子树不再产出候选）。"""
        raise NotImplementedError

    def leaf_step_ids(self) -> Set[str]:
        """策略树引用到的全部叶子步骤 id。"""
        raise NotImplementedError


class StepRef(AuthRequirement):
    """叶子：要求某个具体步骤被满足。"""

    def __init__(self, step_id: str) -> None:
        self.step_id = step_id

    def is_satisfied(self, satisfied: Set[str]) -> bool:
        return self.step_id in satisfied

    def candidates(self, satisfied: Set[str]) -> Set[str]:
        return set() if self.step_id in satisfied else {self.step_id}

    def leaf_step_ids(self) -> Set[str]:
        return {self.step_id}


class _Composite(AuthRequirement):
    def __init__(self, children: List[AuthRequirement]) -> None:
        self.children = tuple(children)

    def leaf_step_ids(self) -> Set[str]:
        out: Set[str] = set()
        for c in self.children:
            out |= c.leaf_step_ids()
        return out

    def _unsatisfied_candidates(self, satisfied: Set[str]) -> Set[str]:
        out: Set[str] = set()
        for c in self.children:
            if not c.is_satisfied(satisfied):
                out |= c.candidates(satisfied)
        return out


class AllOf(_Composite):
    """AND：全部子项满足。"""

    def is_satisfied(self, satisfied: Set[str]) -> bool:
        return all(c.is_satisfied(satisfied) for c in self.children)

    def candidates(self, satisfied: Set[str]) -> Set[str]:
        return self._unsatisfied_candidates(satisfied)


class AnyOf(_Composite):
    """OR：任一子项满足。"""

    def is_satisfied(self, satisfied: Set[str]) -> bool:
        return any(c.is_satisfied(satisfied) for c in self.children)

    def candidates(self, satisfied: Set[str]) -> Set[str]:
        if self.is_satisfied(satisfied):
            return set()
        return self._unsatisfied_candidates(satisfied)


class NOf(AuthRequirement):
    """N-of-M：至少 ``n`` 个子项满足。"""

    def __init__(self, n: int, children: List[AuthRequirement]) -> None:
        self.n = n
        self.children = tuple(children)

    def _count(self, satisfied: Set[str]) -> int:
        return sum(1 for c in self.children if c.is_satisfied(satisfied))

    def is_satisfied(self, satisfied: Set[str]) -> bool:
        return self._count(satisfied) >= self.n

    def candidates(self, satisfied: Set[str]) -> Set[str]:
        if self.is_satisfied(satisfied):
            return set()
        out: Set[str] = set()
        for c in self.children:
            if not c.is_satisfied(satisfied):
                out |= c.candidates(satisfied)
        return out

    def leaf_step_ids(self) -> Set[str]:
        out: Set[str] = set()
        for c in self.children:
            out |= c.leaf_step_ids()
        return out


# --------------------------------------------------------------------------- 跨请求状态


@dataclass(frozen=True)
class AuthContext:
    """不可变的流程状态。所有 ``with_*`` 返回新副本（不就地修改），可 JSON 序列化供 FlowStore 承载。"""

    flow_id: str
    username: Optional[str] = None
    resolved_user_id: Optional[Any] = None
    mfa_satisfied: bool = False
    attempts: int = 0
    satisfied_steps: frozenset = field(default_factory=frozenset)
    challenges: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    def with_satisfied(self, step_id: str) -> "AuthContext":
        return replace(self, satisfied_steps=self.satisfied_steps | {step_id})

    def with_resolved_user(self, user_id: Any, mfa_satisfied: bool = False) -> "AuthContext":
        return replace(self, resolved_user_id=user_id, mfa_satisfied=mfa_satisfied)

    def with_challenge(self, step_id: str, payload: Dict[str, Any]) -> "AuthContext":
        merged = dict(self.challenges)
        merged[step_id] = payload
        return replace(self, challenges=merged)

    def with_attempt(self) -> "AuthContext":
        return replace(self, attempts=self.attempts + 1)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict（``satisfied_steps`` 转有序 list）。"""
        return {
            "flow_id": self.flow_id,
            "username": self.username,
            "resolved_user_id": self.resolved_user_id,
            "mfa_satisfied": self.mfa_satisfied,
            "attempts": self.attempts,
            "satisfied_steps": sorted(self.satisfied_steps),
            "challenges": dict(self.challenges),
            "data": dict(self.data),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthContext":
        return cls(
            flow_id=d["flow_id"],
            username=d.get("username"),
            resolved_user_id=d.get("resolved_user_id"),
            mfa_satisfied=bool(d.get("mfa_satisfied", False)),
            attempts=int(d.get("attempts", 0)),
            satisfied_steps=frozenset(d.get("satisfied_steps") or []),
            challenges=dict(d.get("challenges") or {}),
            data=dict(d.get("data") or {}),
        )
