"""启动和关闭阶段的单步执行原语。"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from typing import Optional

from app.runtime.log import logger


async def run_startup_step(
    name: str,
    callback: Callable[[], object],
    timeout_seconds: Optional[float] = None,
) -> object:
    """
    执行单个启动阶段并记录耗时，失败时保留原异常和 fail-fast 语义

    :param name: 阶段名称，用于日志标识
    :param callback: 阶段回调，返回值可以是协程
    :param timeout_seconds: 协程回调的超时预算，None 表示不限时
    :return: 回调的返回值，协程回调返回其 await 结果
    """
    started_at = time.perf_counter()
    try:
        result = callback()
        if inspect.isawaitable(result):
            if timeout_seconds:
                result = await asyncio.wait_for(result, timeout=timeout_seconds)
            else:
                result = await result
        return result
    finally:
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        logger.info("启动%s完成，耗时=%.2fms", name, elapsed_ms)


async def run_shutdown_step(
    name: str,
    callback: Callable[[], object],
    timeout_seconds: Optional[float] = None,
) -> None:
    """
    隔离单个关闭阶段的异常，确保后续资源仍有机会释放

    :param name: 阶段名称，用于日志标识
    :param callback: 阶段回调，返回值可以是协程
    :param timeout_seconds: 协程回调的超时预算，None 表示不限时
    """
    try:
        result = callback()
        if inspect.isawaitable(result):
            if timeout_seconds:
                await asyncio.wait_for(result, timeout=timeout_seconds)
            else:
                await result
    except Exception as err:
        logger.error(f"关闭{name}失败：{err}")
