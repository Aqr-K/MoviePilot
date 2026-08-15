"""模块契约校验。

判定一个候选类能否作为系统模块被注册：抽象方法已落地、生命周期与类型声明方法齐备且
签名不索取额外必填参。模块基类本身由启动组合根经 ``configure_module_base`` 注入，本模块
不反向依赖 ``app.modules``。
"""
import inspect
from typing import List, Optional, Tuple

# 模块必须提供的生命周期与类型声明方法
CONTRACT_METHODS: Tuple[str, ...] = (
    "init_module",
    "init_setting",
    "stop",
    "test",
    "get_type",
    "get_subtype",
)

_module_base: Optional[type] = None


def configure_module_base(module_base: type) -> None:
    """
    注入模块基类，使契约校验能区分真模块与任意可调用类

    :param module_base: 系统模块基类
    """
    global _module_base
    _module_base = module_base


def verify_module_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验候选类是否满足系统模块契约

    :param module_cls: 待校验的模块类
    :return: (是否通过, 失败原因列表)
    """
    if not isinstance(module_cls, type):
        return False, ["不是类对象"]
    reasons: List[str] = []
    # 基类未注入时跳过该项，使脱离启动组合根的场景仍可校验其余条目
    if _module_base is not None and not issubclass(module_cls, _module_base):
        reasons.append(f"未继承 {_module_base.__name__}")
    abstracts = getattr(module_cls, "__abstractmethods__", frozenset())
    if abstracts:
        reasons.append(f"抽象方法未实现：{sorted(abstracts)}")
    for name in CONTRACT_METHODS:
        func = getattr(module_cls, name, None)
        if not callable(func):
            reasons.append(f"缺少契约方法：{name}")
            continue
        extra = _required_extra_parameters(func)
        if extra:
            reasons.append(f"{name} 签名不兼容：要求额外必填参 {extra}")
    return not reasons, reasons


def _required_extra_parameters(func) -> List[str]:
    """
    列出可调用对象除 self/cls 外的必填参数，无法内省时视为无

    :param func: 待检查的可调用对象
    :return: 必填参数名列表
    """
    try:
        parameters = inspect.signature(func).parameters.values()
    except (ValueError, TypeError):
        return []
    return [
        parameter.name
        for parameter in parameters
        if parameter.name not in ("self", "cls")
        and parameter.kind in (
            parameter.POSITIONAL_ONLY,
            parameter.POSITIONAL_OR_KEYWORD,
            parameter.KEYWORD_ONLY,
        )
        and parameter.default is parameter.empty
    ]
