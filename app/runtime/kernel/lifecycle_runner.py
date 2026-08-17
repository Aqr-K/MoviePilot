"""生命周期组件的顺序执行引擎。"""

from __future__ import annotations

from collections.abc import Iterable

from app.runtime.kernel.lifecycle import LifecycleComponent
from app.runtime.kernel.step_runner import run_shutdown_step, run_startup_step


async def start_lifecycle_components(
    components: Iterable[LifecycleComponent],
) -> None:
    """
    按 start_order 升序执行组件的启动回调

    任一阶段失败都会中断启动并向上抛出，未声明 start 的组件被跳过。

    :param components: 已按运行模式筛选的组件清单
    """
    for component in sorted(
        (item for item in components if item.start is not None),
        key=lambda item: item.start_order or 0,
    ):
        await run_startup_step(
            component.name,
            component.start,
            component.start_timeout_seconds,
        )


async def stop_lifecycle_components(
    components: Iterable[LifecycleComponent],
) -> None:
    """
    按 stop_order 升序执行组件的关闭回调

    单个组件关闭失败不影响后续组件，未声明 stop 的组件被跳过。

    :param components: 已按运行模式筛选的组件清单
    """
    for component in sorted(
        (item for item in components if item.stop is not None),
        key=lambda item: item.stop_order or 0,
    ):
        await run_shutdown_step(
            component.name,
            component.stop,
            component.stop_timeout_seconds,
        )
