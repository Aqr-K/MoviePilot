# -*- coding: utf-8 -*-
"""
命名认证流程注册表（db-free）—— 让插件声明**自定义流程形状**（组合策略），而不止于贡献单个步骤。

认证步骤（凭证 / MFA 因子 / 重定向）已可经统一 ``provides_auth_steps`` SPI 插拔；本注册表补上
"流程形状"维度：插件交出一个 ``IFlowSpec``（``flow_id`` + ``mfa_requirement``），
即可声明如 2-of-3 强 MFA、AllOf 强制多因子等组合策略。上层（端点）按 ``flow_id`` 选用对应策略。

沿用统一注册纪律（owner-scoped、契约校验、flow_id 碰撞检测，见 ``registry.py``）。
"""
from typing import Any, List, Optional, Protocol, Tuple, runtime_checkable

from app.core.auth.identifiers import is_valid_identifier
from app.core.auth.registry import OwnerScopedRegistry


@runtime_checkable
class IFlowSpec(Protocol):
    """认证流程规格契约。

    - ``flow_id``：唯一标识（如 "default" / "high-assurance"）；
    - ``mfa_requirement(factor_steps)``：据该用户已装配的因子步骤返回组合策略 ``AuthRequirement``
      （``AnyOf`` / ``NOf`` / ``AllOf`` 任意嵌套），决定"需要满足哪些第二因子"。
    """

    flow_id: str

    def mfa_requirement(self, factor_steps: List[Any]) -> Any: ...


def _is_empty_true(spec: Any) -> bool:
    """检测流程规格是否"空真"（empty-true）——其组合策略对空 satisfied 集即满足（如 ``AllOf([])`` / ``NOf(0)``）。

    空真意味着用户**未完成任何因子**时该流程即视为 MFA 通过（vacuous bypass），是 MFA 绕过漏洞（R5/M2）。
    既查显式 ``requirement`` 属性，也试以空因子集求值 ``mfa_requirement([])``——只要任一路径空真即判定为真。
    求值异常不在此处判定（``callable`` 校验已在外层覆盖），以免误伤。
    """
    candidates: List[Any] = []
    req_attr = getattr(spec, "requirement", None)
    if req_attr is not None:
        candidates.append(req_attr)
    mfa = getattr(spec, "mfa_requirement", None)
    if callable(mfa):
        try:
            candidates.append(mfa([]))
        except Exception:  # noqa: BLE001 —— 求值异常交由 callable 契约判定，不据此判空真
            pass
    for req in candidates:
        try:
            if req is not None and req.is_satisfied(frozenset()):
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def verify_flow_spec_contract(spec: Any) -> Tuple[bool, List[str]]:
    """校验对象是否满足 ``IFlowSpec`` 契约。返回 (是否通过, 失败原因列表)。

    除 flow_id / mfa_requirement 形态外，**拒绝"空真"规格**：其组合策略对空集即满足者会 vacuous 绕过
    MFA（如插件注册 flow_id="default" 且 mfa_requirement 返回 ``AllOf([])``/``NOf(0)``），安全上必须拒绝。
    """
    reasons: List[str] = []
    if not is_valid_identifier(getattr(spec, "flow_id", None)):
        reasons.append("flow_id 必须为 1–32 位字母、数字或连字符")
    if not callable(getattr(spec, "mfa_requirement", None)):
        reasons.append("须实现 mfa_requirement 方法")
    if _is_empty_true(spec):
        reasons.append("组合策略对空集即满足（空真），将 vacuous 绕过 MFA，拒绝注册")
    return (not reasons), reasons


class FlowSpecRegistry(OwnerScopedRegistry):
    """命名流程规格注册表：按 ``flow_id`` 单索引、带 owner。"""

    def _id_of(self, item: Any) -> str:
        return item.flow_id

    def _validate(self, item: Any) -> Tuple[bool, List[str]]:
        return verify_flow_spec_contract(item)


_REGISTRY = FlowSpecRegistry()


def register_auth_flow(spec: Any, owner: Optional[str]) -> Tuple[bool, str]:
    """注册一个命名流程规格（契约校验 + flow_id 碰撞检测）。"""
    return _REGISTRY.register(spec, owner)


def unregister_auth_flows(owner: Optional[str]) -> None:
    """卸载某 owner（插件）注册的全部流程规格。"""
    _REGISTRY.unregister(owner)


def get_auth_flow(flow_id: str) -> Optional[Any]:
    """按 flow_id 取已注册流程规格，不存在返回 None。"""
    return _REGISTRY.get(flow_id)


def registered_flow_ids() -> List[str]:
    """已注册的 flow_id 列表。"""
    return _REGISTRY.ids()


def all_auth_flows() -> List[Any]:
    """全部已注册流程规格。"""
    return _REGISTRY.all()
