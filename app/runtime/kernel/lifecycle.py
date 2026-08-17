"""应用启动和关闭组件的声明模型。"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional


class LifecycleMode(StrEnum):
    """声明组件在哪一种应用运行模式下启用。"""

    ALWAYS = "always"
    NORMAL_ONLY = "normal_only"


class LifecycleFailurePolicy(StrEnum):
    """声明生命周期回调失败后的控制流策略。"""

    FAIL_FAST = "fail_fast"
    CONTINUE = "continue"


@dataclass(frozen=True, slots=True)
class LifecycleComponent:
    """描述一个可检查的启动或关闭组件及其顺序和失败策略。"""

    name: str
    dependencies: tuple[str, ...] = ()
    mode: LifecycleMode = LifecycleMode.ALWAYS
    start: Optional[Callable[[], object]] = None
    stop: Optional[Callable[[], object]] = None
    start_order: Optional[int] = None
    stop_order: Optional[int] = None
    start_timeout_seconds: Optional[float] = None
    stop_timeout_seconds: Optional[float] = None
    start_failure: LifecycleFailurePolicy = LifecycleFailurePolicy.FAIL_FAST
    stop_failure: LifecycleFailurePolicy = LifecycleFailurePolicy.CONTINUE

    def enabled(self, safe_mode: bool) -> bool:
        """
        判断组件是否应在当前安全模式设置下启用

        :param safe_mode: 当前是否处于安全模式
        :return: 启用返回 True，跳过返回 False
        """
        return self.mode is LifecycleMode.ALWAYS or not safe_mode


def select_enabled_components(
    components: Iterable[LifecycleComponent],
    *,
    safe_mode: bool,
) -> tuple[LifecycleComponent, ...]:
    """
    按运行模式筛选启用的生命周期组件

    :param components: 待筛选的组件清单
    :param safe_mode: 当前是否处于安全模式
    :return: 保持原有声明顺序的启用组件元组
    """
    return tuple(
        component for component in components if component.enabled(safe_mode)
    )


def lifecycle_manifest(
    components: Iterable[LifecycleComponent],
    *,
    safe_mode: bool,
) -> tuple[dict[str, object], ...]:
    """
    导出当前模式下启用组件的稳定、可序列化生命周期清单

    :param components: 待导出的组件清单
    :param safe_mode: 当前是否处于安全模式
    :return: 每项描述组件依赖、模式、顺序、超时和失败策略的字典元组
    """
    return tuple(
        {
            "name": component.name,
            "dependencies": component.dependencies,
            "mode": component.mode.value,
            "start_order": component.start_order,
            "stop_order": component.stop_order,
            "start_timeout_seconds": component.start_timeout_seconds,
            "stop_timeout_seconds": component.stop_timeout_seconds,
            "start_failure": component.start_failure.value,
            "stop_failure": component.stop_failure.value,
        }
        for component in select_enabled_components(components, safe_mode=safe_mode)
    )
