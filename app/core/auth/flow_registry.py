# -*- coding: utf-8 -*-
"""
命名认证流程注册表（db-free）—— 让插件声明**自定义流程形状**（组合策略），而不止于贡献单个步骤。

步骤（凭证 provider / MFA 因子）已可经 ``provides_credential_providers`` / ``provides_mfa_factors``
插拔；本注册表补上"流程形状"维度：插件交出一个 ``IFlowSpec``（``flow_id`` + ``mfa_requirement``），
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


def verify_flow_spec_contract(spec: Any) -> Tuple[bool, List[str]]:
    """校验对象是否满足 ``IFlowSpec`` 契约。返回 (是否通过, 失败原因列表)。"""
    reasons: List[str] = []
    if not is_valid_identifier(getattr(spec, "flow_id", None)):
        reasons.append("flow_id 必须为 1–32 位字母、数字或连字符")
    if not callable(getattr(spec, "mfa_requirement", None)):
        reasons.append("须实现 mfa_requirement 方法")
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
