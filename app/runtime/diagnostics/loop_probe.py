"""事件循环延迟探针：常驻协程测量事件循环调度延迟，维护滑动窗口统计并暴露给外部诊断。"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from typing import Optional

from app.runtime.config import settings
from app.runtime.log import logger


@dataclass(frozen=True, slots=True)
class LoopLatencySnapshot:
    """事件循环延迟滑动窗口的一次统计快照。"""

    sample_count: int
    last_seconds: float
    p50_seconds: float
    p95_seconds: float
    max_seconds: float
    threshold_seconds: float
    exceeded_threshold: bool


def _percentile(sorted_samples: list[float], percentile: float) -> float:
    """按百分位取滑动窗口中对应位置的样本值。

    :param sorted_samples: 已升序排序的样本列表
    :param percentile: 0～1 之间的百分位
    :return: 对应位置样本值，样本为空时返回 0
    """
    if not sorted_samples:
        return 0.0
    index = min(len(sorted_samples) - 1, int(len(sorted_samples) * percentile))
    return sorted_samples[index]


class EventLoopLatencyProbe:
    """常驻协程周期性测量事件循环调度延迟，并维护滑动窗口统计。"""

    def __init__(
        self,
        *,
        interval_seconds: float,
        window_size: int,
        warn_threshold_seconds: float,
    ) -> None:
        """
        :param interval_seconds: 探测周期，每次 `asyncio.sleep` 的期望时长
        :param window_size: 滑动窗口保留的最近样本数量
        :param warn_threshold_seconds: 单次采样延迟超过该值即记 WARNING 日志
        """
        self._interval_seconds = interval_seconds
        self._warn_threshold_seconds = warn_threshold_seconds
        self._samples: deque[float] = deque(maxlen=window_size)
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """在当前运行中的事件循环上创建探针后台任务，重复调用是幂等的。"""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.get_event_loop().create_task(self._run())

    async def stop(self) -> None:
        """取消探针后台任务并等待其退出。"""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _run(self) -> None:
        """周期性 sleep 并记录实际耗时与期望耗时的偏差。"""
        loop = asyncio.get_running_loop()
        while True:
            started_at = loop.time()
            await asyncio.sleep(self._interval_seconds)
            actual = loop.time() - started_at
            self._record(max(0.0, actual - self._interval_seconds))

    def _record(self, latency_seconds: float) -> None:
        """写入一次延迟采样，超过阈值时记 WARNING 日志。"""
        self._samples.append(latency_seconds)
        if latency_seconds >= self._warn_threshold_seconds:
            logger.warning(
                "事件循环延迟探针检测到高延迟：%.1fms（阈值 %.1fms）",
                latency_seconds * 1000,
                self._warn_threshold_seconds * 1000,
            )

    def snapshot(self) -> LoopLatencySnapshot:
        """返回当前滑动窗口的延迟统计快照。"""
        if not self._samples:
            return LoopLatencySnapshot(
                sample_count=0,
                last_seconds=0.0,
                p50_seconds=0.0,
                p95_seconds=0.0,
                max_seconds=0.0,
                threshold_seconds=self._warn_threshold_seconds,
                exceeded_threshold=False,
            )
        sorted_samples = sorted(self._samples)
        max_seconds = sorted_samples[-1]
        return LoopLatencySnapshot(
            sample_count=len(sorted_samples),
            last_seconds=self._samples[-1],
            p50_seconds=_percentile(sorted_samples, 0.50),
            p95_seconds=_percentile(sorted_samples, 0.95),
            max_seconds=max_seconds,
            threshold_seconds=self._warn_threshold_seconds,
            exceeded_threshold=max_seconds >= self._warn_threshold_seconds,
        )


_probe: Optional[EventLoopLatencyProbe] = None


def get_loop_latency_probe() -> Optional[EventLoopLatencyProbe]:
    """返回当前进程内的事件循环延迟探针实例，未启动时为 None。"""
    return _probe


def start_loop_latency_probe() -> Optional[EventLoopLatencyProbe]:
    """按配置创建（如尚未创建）并启动事件循环延迟探针，同时对齐 asyncio 慢回调阈值。

    :return: 探针实例；`LOOP_LATENCY_PROBE_ENABLE` 关闭时返回 None 且不创建实例
    """
    global _probe
    if not settings.LOOP_LATENCY_PROBE_ENABLE:
        _probe = None
        return None
    if _probe is None:
        _probe = EventLoopLatencyProbe(
            interval_seconds=settings.LOOP_LATENCY_PROBE_INTERVAL_SECONDS,
            window_size=settings.LOOP_LATENCY_PROBE_WINDOW_SIZE,
            warn_threshold_seconds=settings.LOOP_LATENCY_WARN_THRESHOLD_SECONDS,
        )
    _probe.start()
    asyncio.get_event_loop().slow_callback_duration = (
        settings.LOOP_SLOW_CALLBACK_DURATION_SECONDS
    )
    return _probe


async def stop_loop_latency_probe() -> None:
    """停止事件循环延迟探针并清空进程内实例引用。"""
    global _probe
    probe, _probe = _probe, None
    if probe is not None:
        await probe.stop()
