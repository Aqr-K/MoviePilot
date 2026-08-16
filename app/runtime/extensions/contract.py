"""模块与扩展点契约校验。

判定一个候选类能否作为系统模块被注册：抽象方法已落地、生命周期与类型声明方法齐备且
签名不索取额外必填参。模块基类本身由启动组合根经 ``configure_module_base`` 注入，本模块
不反向依赖 ``app.modules``；智能体工具基类同理经 ``configure_agent_tool_base`` 注入。
"""
import inspect
from typing import Any, List, Optional, Tuple

# 模块必须提供的生命周期与类型声明方法
CONTRACT_METHODS: Tuple[str, ...] = (
    "init_module",
    "init_setting",
    "stop",
    "test",
    "get_type",
    "get_subtype",
)

# 智能体工具必须提供的标识属性
AGENT_TOOL_ATTRIBUTES: Tuple[str, ...] = ("name", "description")

_module_base: Optional[type] = None
_agent_tool_base: Optional[type] = None


def configure_module_base(module_base: type) -> None:
    """
    注入模块基类，使契约校验能区分真模块与任意可调用类

    :param module_base: 系统模块基类
    """
    global _module_base
    _module_base = module_base


def configure_agent_tool_base(tool_base: type) -> None:
    """
    注入智能体工具基类，使契约校验能区分真工具与任意类

    :param tool_base: 智能体工具基类
    """
    global _agent_tool_base
    _agent_tool_base = tool_base


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


def verify_module_type(module_cls: type, expected_type: Any) -> Tuple[bool, List[str]]:
    """
    在系统模块契约之上追加模块类型校验

    ``get_type()`` 需要在类上就能取值才可校验；写成实例方法时无法在注册前判定，此时只
    校验基础契约，由分发链按实际类型自行取舍。

    :param module_cls: 待校验的模块类
    :param expected_type: 期望的模块类型
    :return: (是否通过, 失败原因列表)
    """
    passed, reasons = verify_module_contract(module_cls)
    if not passed:
        return False, reasons
    getter = getattr(module_cls, "get_type", None)
    try:
        actual_type = getter()
    except TypeError:
        return True, []
    except Exception as err:
        return False, [f"get_type 取值失败：{err}"]
    if actual_type != expected_type:
        return False, [f"模块类型不符：声明为 {expected_type}，实际为 {actual_type}"]
    return True, []


def verify_agent_tool_contract(tool_cls: type) -> Tuple[bool, List[str]]:
    """
    校验候选类是否满足智能体工具契约

    工具需继承工具基类、抽象方法已落地、具备非空的 name 与 description，并实现
    异步的 run。基类未注入时跳过继承项，使脱离启动组合根的场景仍可校验其余条目。

    :param tool_cls: 待校验的工具类
    :return: (是否通过, 失败原因列表)
    """
    if not isinstance(tool_cls, type):
        return False, ["不是类对象"]
    reasons: List[str] = []
    if _agent_tool_base is not None and not issubclass(tool_cls, _agent_tool_base):
        reasons.append(f"未继承 {_agent_tool_base.__name__}")
    abstracts = getattr(tool_cls, "__abstractmethods__", frozenset())
    if abstracts:
        reasons.append(f"抽象方法未实现：{sorted(abstracts)}")
    for attribute in AGENT_TOOL_ATTRIBUTES:
        value = getattr(tool_cls, attribute, None)
        # 属性可能是描述符或 pydantic 字段，取不到字符串时只判空
        if not value or not isinstance(value, str):
            reasons.append(f"缺少或非字符串的属性：{attribute}")
    run = getattr(tool_cls, "run", None)
    if not callable(run):
        reasons.append("缺少契约方法：run")
    elif not inspect.iscoroutinefunction(run):
        reasons.append("run 必须是异步方法")
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
