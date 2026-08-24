"""定时作业看门狗：记录作业墙钟执行时长，对仍在运行且已超时的作业点名告警。

看门狗只观测不干预：Python 没有安全终止线程的手段，强行终止一个执行到一半的
作业会留下不一致的中间状态，因此超时作业只记日志并暴露给外部诊断。

作业结束后才发出的调度器事件看不到「正在超时运行中」这一状态，所以在途作业由
一条独立采样线程巡检——它不占用调度器线程池，池子被挂起的作业占满时仍能告警。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from itertools import count
from typing import Callable, Dict, Optional, Tuple

from app.runtime.config import settings
from app.runtime.log import logger

# 在途作业连续为空多少个采样周期后采样线程退出
WATCHDOG_IDLE_SAMPLES_BEFORE_EXIT = 3
# 采样线程的最小休眠秒数，避免配置成 0 导致空转
WATCHDOG_MIN_SAMPLE_INTERVAL = 0.01


def watchdog_enabled() -> bool:
    """读取看门狗总开关。

    :return: 是否启用看门狗
    """
    return bool(settings.SCHEDULER_WATCHDOG_ENABLE)


def watchdog_overdue_seconds() -> float:
    """读取作业超时判定阈值。

    :return: 单次执行超过该秒数即判定超时
    """
    return float(settings.SCHEDULER_WATCHDOG_JOB_OVERDUE_SECONDS)


def watchdog_sample_interval() -> float:
    """读取采样线程的巡检周期。

    :return: 巡检周期秒数
    """
    return float(settings.SCHEDULER_WATCHDOG_SAMPLE_INTERVAL_SECONDS)


@dataclass(frozen=True, slots=True)
class RunningJobSnapshot:
    """一次在途作业执行的只读快照。

    :param job_id: 作业标识
    :param job_name: 作业显示名
    :param plugin_id: 插件作业所属插件标识，非插件作业为 None
    :param provider_name: 作业提供方显示名
    :param elapsed_seconds: 已执行秒数
    :param overdue: 是否已超过超时阈值
    """

    job_id: str
    job_name: Optional[str]
    plugin_id: Optional[str]
    provider_name: Optional[str]
    elapsed_seconds: float
    overdue: bool


@dataclass(frozen=True, slots=True)
class JobRunOutcome:
    """一次作业执行结束时的时长判定。

    :param elapsed_seconds: 本次执行的墙钟耗时
    :param overdue: 本次执行是否超过超时阈值
    """

    elapsed_seconds: float
    overdue: bool


@dataclass
class _RunningJob:
    """在途作业执行的可变记录。"""

    job_id: str
    job_name: Optional[str]
    plugin_id: Optional[str]
    provider_name: Optional[str]
    started_at: float
    warned: bool = False


def describe_job(job_id: str, job_name: Optional[str], plugin_id: Optional[str]) -> str:
    """拼接作业在日志中的点名描述。

    :param job_id: 作业标识
    :param job_name: 作业显示名
    :param plugin_id: 插件作业所属插件标识
    :return: 形如 ``名称(标识)[插件 X]`` 的描述
    """
    described = f"{job_name}({job_id})" if job_name else job_id
    return f"{described}[插件 {plugin_id}]" if plugin_id else described


class JobWatchdog:
    """按作业执行记录墙钟时长，并巡检在途作业是否超时。"""

    def __init__(
        self,
        *,
        enabled_provider: Callable[[], bool] = watchdog_enabled,
        overdue_provider: Callable[[], float] = watchdog_overdue_seconds,
        interval_provider: Callable[[], float] = watchdog_sample_interval,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """按开关、阈值与时钟来源初始化在途作业表。

        :param enabled_provider: 看门狗总开关的取值来源
        :param overdue_provider: 超时阈值秒数的取值来源
        :param interval_provider: 采样线程巡检周期秒数的取值来源
        :param clock: 单调时钟，用于计算执行时长
        """
        self._enabled_provider = enabled_provider
        self._overdue_provider = overdue_provider
        self._interval_provider = interval_provider
        self._clock = clock
        self._lock = threading.Lock()
        self._running: Dict[int, _RunningJob] = {}
        self._misfires: Dict[str, int] = {}
        self._tokens = count(1)
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None

    def begin(
        self,
        job_id: str,
        *,
        job_name: Optional[str] = None,
        plugin_id: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> int:
        """登记一次作业执行的开始时刻。

        :param job_id: 作业标识
        :param job_name: 作业显示名
        :param plugin_id: 插件作业所属插件标识
        :param provider_name: 作业提供方显示名
        :return: 本次执行的登记令牌，收口时用它摘除记录
        """
        token = next(self._tokens)
        sampler: Optional[threading.Thread] = None
        with self._lock:
            self._running[token] = _RunningJob(
                job_id=job_id,
                job_name=job_name,
                plugin_id=plugin_id,
                provider_name=provider_name,
                started_at=self._clock(),
            )
            # 与采样线程的退出判定共用同一把锁：要么线程看到本次在途记录而继续巡检，
            # 要么它已把自己摘干净，这里补启一条新线程，不会出现无人巡检的空窗
            if self._enabled_provider() and self._sampler_needs_start():
                stop_event = threading.Event()
                sampler = threading.Thread(
                    target=self._run_sampler,
                    args=(stop_event,),
                    name="scheduler-job-watchdog",
                    daemon=True,
                )
                self._thread = sampler
                self._stop_event = stop_event
        if sampler:
            sampler.start()
        return token

    def end(self, token: int) -> JobRunOutcome:
        """摘除一次作业执行的在途记录并给出时长判定。

        :param token: `begin` 返回的登记令牌
        :return: 本次执行的耗时与是否超时
        """
        with self._lock:
            entry = self._running.pop(token, None)
            if entry is None:
                return JobRunOutcome(elapsed_seconds=0.0, overdue=False)
            elapsed = self._clock() - entry.started_at
            return JobRunOutcome(
                elapsed_seconds=elapsed,
                overdue=self._is_overdue(elapsed),
            )

    def running_jobs(self) -> Tuple[RunningJobSnapshot, ...]:
        """列出全部在途作业执行。

        :return: 在途作业快照元组
        """
        with self._lock:
            return tuple(self._snapshot(entry) for entry in self._running.values())

    def overdue_jobs(self) -> Tuple[RunningJobSnapshot, ...]:
        """列出仍在运行且已超时的作业执行。

        :return: 超时作业快照元组
        """
        return tuple(item for item in self.running_jobs() if item.overdue)

    def sample(self) -> Tuple[RunningJobSnapshot, ...]:
        """巡检一次在途作业，对首次判定超时的执行点名告警。

        同一次执行只告警一次，长时间挂起的作业不会反复刷屏。
        :return: 本次巡检判定为超时的作业快照元组
        """
        overdue = []
        with self._lock:
            for entry in self._running.values():
                elapsed = self._clock() - entry.started_at
                if not self._is_overdue(elapsed) or entry.warned:
                    continue
                entry.warned = True
                overdue.append(self._snapshot(entry))
        for item in overdue:
            logger.warning(
                f"定时作业 {describe_job(item.job_id, item.job_name, item.plugin_id)} "
                f"已运行 {item.elapsed_seconds:.0f} 秒仍未结束，"
                f"超过看门狗阈值 {self._overdue_provider():.0f} 秒"
            )
        return tuple(overdue)

    def record_misfire(self, job_id: str) -> int:
        """累计一次作业错过触发。

        :param job_id: 作业标识
        :return: 该作业累计错过触发的次数
        """
        with self._lock:
            counted = self._misfires.get(job_id, 0) + 1
            self._misfires[job_id] = counted
            return counted

    def misfires(self) -> Dict[str, int]:
        """列出各作业累计错过触发的次数。

        :return: 作业标识到次数的映射副本
        """
        with self._lock:
            return dict(self._misfires)

    def overdue_seconds(self) -> float:
        """读取当前生效的超时判定阈值。

        :return: 超时阈值秒数
        """
        return self._overdue_provider()

    def sampler_alive(self) -> bool:
        """判断采样线程是否在运行。

        :return: 采样线程存活时返回 True
        """
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        """停止采样线程。

        :return: 无返回值
        """
        with self._lock:
            stop_event = self._stop_event
            self._thread = None
            self._stop_event = None
        if stop_event:
            stop_event.set()

    def _sampler_needs_start(self) -> bool:
        """判断当前是否缺少可用的采样线程。

        :return: 需要新建采样线程时返回 True
        """
        return self._thread is None or not self._thread.is_alive()

    def _run_sampler(self, stop_event: threading.Event) -> None:
        """采样线程主体：周期性巡检在途作业，空闲若干周期后退出。

        :param stop_event: 停止信号
        :return: 无返回值
        """
        idle_rounds = 0
        while not stop_event.wait(
            max(WATCHDOG_MIN_SAMPLE_INTERVAL, self._interval_provider())
        ):
            self.sample()
            with self._lock:
                if self._running:
                    idle_rounds = 0
                    continue
                idle_rounds += 1
                if idle_rounds < WATCHDOG_IDLE_SAMPLES_BEFORE_EXIT:
                    continue
                if self._stop_event is stop_event:
                    self._thread = None
                    self._stop_event = None
                return

    def _is_overdue(self, elapsed: float) -> bool:
        """判断执行时长是否已超过阈值。

        :param elapsed: 已执行秒数
        :return: 看门狗启用且时长超过阈值时返回 True
        """
        if not self._enabled_provider():
            return False
        return elapsed > self._overdue_provider()

    def _snapshot(self, entry: _RunningJob) -> RunningJobSnapshot:
        """按在途记录生成只读快照。

        :param entry: 在途作业记录
        :return: 在途作业快照
        """
        elapsed = self._clock() - entry.started_at
        return RunningJobSnapshot(
            job_id=entry.job_id,
            job_name=entry.job_name,
            plugin_id=entry.plugin_id,
            provider_name=entry.provider_name,
            elapsed_seconds=elapsed,
            overdue=self._is_overdue(elapsed),
        )
