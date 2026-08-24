"""插件定时作业熔断：按作业记录连续失败，在闭合、打开与半开三态间迁移。

熔断作用域是单条定时作业而不是整个插件：一条定时任务连续失败不代表该插件提供
的 API、页面、事件处理都该停，按插件停机会把一次局部故障放大成整体不可用。

自动跳过执行是破坏性动作，因此跳闸阈值按「连续失败」而非失败率计数，中途任何
一次成功都会清零；两次失败相隔超过窗口即视为互不相关，偶发抖动不会累积成跳闸。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Iterable, Optional, Tuple

from app.runtime.config import settings
from app.runtime.log import logger
from app.scheduler.watchdog import describe_job

# 连续失败阈值的下限，低于 3 次极易被偶发抖动触发
PLUGIN_BREAKER_MIN_THRESHOLD = 3


def breaker_enabled() -> bool:
    """读取插件作业熔断总开关。

    :return: 是否允许跳过执行；关闭时只按同一阈值告警
    """
    return bool(settings.PLUGIN_JOB_BREAKER_ENABLE)


def breaker_failure_threshold() -> int:
    """读取跳闸所需的连续失败次数。

    :return: 连续失败次数，不低于 `PLUGIN_BREAKER_MIN_THRESHOLD`
    """
    return max(
        PLUGIN_BREAKER_MIN_THRESHOLD,
        int(settings.PLUGIN_JOB_BREAKER_FAILURE_THRESHOLD),
    )


def breaker_failure_window() -> float:
    """读取连续失败的有效窗口。

    :return: 相邻两次失败相隔超过该秒数即重新计数
    """
    return float(settings.PLUGIN_JOB_BREAKER_FAILURE_WINDOW_SECONDS)


def breaker_recovery_seconds() -> float:
    """读取跳闸后放行半开试探的等待时长。

    :return: 等待秒数
    """
    return float(settings.PLUGIN_JOB_BREAKER_RECOVERY_SECONDS)


class CircuitState(str, Enum):
    """作业熔断开关的状态。

    - CLOSED：正常放行
    - OPEN：跳过执行，等待恢复间隔
    - HALF_OPEN：已放行一次试探执行，结果决定回到 CLOSED 还是退回 OPEN
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class CircuitSnapshot:
    """一条作业熔断记录的只读快照。

    :param job_id: 作业标识
    :param job_name: 作业显示名
    :param plugin_id: 作业所属插件标识
    :param state: 当前熔断状态
    :param consecutive_failures: 当前连续失败次数
    :param threshold: 当前生效的跳闸阈值
    :param degraded: 连续失败是否已达阈值
    :param enforced: 达阈值后是否真的跳过执行
    :param last_error: 最近一次失败原因
    :param skipped_runs: 跳闸期间累计跳过的触发次数
    :param trip_count: 累计跳闸次数
    """

    job_id: str
    job_name: Optional[str]
    plugin_id: Optional[str]
    state: CircuitState
    consecutive_failures: int
    threshold: int
    degraded: bool
    enforced: bool
    last_error: Optional[str]
    skipped_runs: int
    trip_count: int


@dataclass
class _Circuit:
    """一条作业熔断记录的可变状态。"""

    job_id: str
    job_name: Optional[str] = None
    plugin_id: Optional[str] = None
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    last_failure_at: Optional[float] = None
    last_error: Optional[str] = None
    opened_at: Optional[float] = None
    skipped_runs: int = 0
    trip_count: int = 0


class JobCircuitBreaker:
    """按作业维护连续失败计数与三态熔断开关。

    只有出过故障的作业才占用记录：一次成功即把记录整条丢弃，映射规模与故障作业
    数量同阶，不随作业执行次数或插件启停增长。
    """

    def __init__(
        self,
        *,
        enabled_provider: Callable[[], bool] = breaker_enabled,
        threshold_provider: Callable[[], int] = breaker_failure_threshold,
        window_provider: Callable[[], float] = breaker_failure_window,
        recovery_provider: Callable[[], float] = breaker_recovery_seconds,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """按开关、阈值与时钟来源初始化熔断记录映射。

        :param enabled_provider: 熔断总开关的取值来源
        :param threshold_provider: 跳闸所需连续失败次数的取值来源
        :param window_provider: 连续失败有效窗口秒数的取值来源
        :param recovery_provider: 半开试探等待秒数的取值来源
        :param clock: 单调时钟
        """
        self._enabled_provider = enabled_provider
        self._threshold_provider = threshold_provider
        self._window_provider = window_provider
        self._recovery_provider = recovery_provider
        self._clock = clock
        self._lock = threading.Lock()
        self._circuits: Dict[str, _Circuit] = {}

    def allow(
        self,
        job_id: str,
        *,
        job_name: Optional[str] = None,
        plugin_id: Optional[str] = None,
    ) -> bool:
        """判断本次触发是否放行执行。

        跳闸期满后只放行一次半开试探，试探在途期间的其余触发继续跳过。
        :param job_id: 作业标识
        :param job_name: 作业显示名
        :param plugin_id: 作业所属插件标识
        :return: 放行返回 True，跳过返回 False
        """
        message = None
        with self._lock:
            circuit = self._circuits.get(job_id)
            if circuit is None or not self._enabled_provider():
                return True
            self._describe(circuit, job_name, plugin_id)
            if circuit.state is CircuitState.CLOSED:
                return True
            recovery = self._recovery_provider()
            if (
                circuit.state is CircuitState.OPEN
                and circuit.opened_at is not None
                and self._clock() - circuit.opened_at >= recovery
            ):
                circuit.state = CircuitState.HALF_OPEN
                message = (
                    f"插件定时作业 {self._describe_job(circuit)} 熔断已满 "
                    f"{recovery:.0f} 秒，放行一次试探执行"
                )
            else:
                circuit.skipped_runs += 1
                logger.info(
                    f"插件定时作业 {self._describe_job(circuit)} 处于熔断状态，"
                    f"跳过本次触发（累计跳过 {circuit.skipped_runs} 次）"
                )
                return False
        logger.info(message)
        return True

    def record_failure(
        self,
        job_id: str,
        *,
        reason: str,
        job_name: Optional[str] = None,
        plugin_id: Optional[str] = None,
    ) -> CircuitState:
        """记录一次作业执行失败并按结果迁移状态。

        :param job_id: 作业标识
        :param job_name: 作业显示名
        :param plugin_id: 作业所属插件标识
        :param reason: 失败原因
        :return: 记录后的熔断状态
        """
        warning = None
        with self._lock:
            circuit = self._circuits.get(job_id)
            if circuit is None:
                circuit = _Circuit(job_id=job_id)
                self._circuits[job_id] = circuit
            self._describe(circuit, job_name, plugin_id)
            circuit.last_error = reason
            now = self._clock()
            window = self._window_provider()
            stale = (
                circuit.state is CircuitState.CLOSED
                and circuit.last_failure_at is not None
                and now - circuit.last_failure_at > window
            )
            circuit.consecutive_failures = 1 if stale else circuit.consecutive_failures + 1
            circuit.last_failure_at = now
            threshold = self._threshold_provider()
            if circuit.state is CircuitState.HALF_OPEN:
                self._trip(circuit, now)
                warning = (
                    f"插件定时作业 {self._describe_job(circuit)} 试探执行仍然失败，"
                    f"重新熔断：{reason}"
                )
            elif circuit.consecutive_failures < threshold:
                pass
            elif self._enabled_provider():
                self._trip(circuit, now)
                warning = (
                    f"插件定时作业 {self._describe_job(circuit)} 已连续失败 "
                    f"{circuit.consecutive_failures} 次，暂停调度，"
                    f"{self._recovery_provider():.0f} 秒后放行一次试探；"
                    f"最近一次失败：{reason}"
                )
            elif circuit.consecutive_failures % threshold == 0:
                # 未启用时按同一阈值周期性点名，既给出降级信号又不至于每次失败都刷屏
                warning = (
                    f"插件定时作业 {self._describe_job(circuit)} 已连续失败 "
                    f"{circuit.consecutive_failures} 次，熔断未启用，仍按原计划触发："
                    f"{reason}"
                )
            state = circuit.state
        if warning:
            logger.warning(warning)
        return state

    def record_success(
        self,
        job_id: str,
        *,
        job_name: Optional[str] = None,
        plugin_id: Optional[str] = None,
    ) -> None:
        """记录一次作业执行成功并释放其故障记录。

        :param job_id: 作业标识
        :param job_name: 作业显示名
        :param plugin_id: 作业所属插件标识
        :return: 无返回值
        """
        message = None
        with self._lock:
            circuit = self._circuits.pop(job_id, None)
            if circuit is None:
                return
            self._describe(circuit, job_name, plugin_id)
            if circuit.state is not CircuitState.CLOSED:
                message = (
                    f"插件定时作业 {self._describe_job(circuit)} 试探执行成功，"
                    f"熔断已解除"
                )
        if message:
            logger.info(message)

    def snapshot(self, job_id: str) -> Optional[CircuitSnapshot]:
        """查询单条作业的熔断记录。

        :param job_id: 作业标识
        :return: 熔断快照，无记录时返回 None
        """
        with self._lock:
            circuit = self._circuits.get(job_id)
            return self._to_snapshot(circuit) if circuit else None

    def snapshots(self) -> Tuple[CircuitSnapshot, ...]:
        """列出全部作业的熔断记录。

        :return: 熔断快照元组
        """
        with self._lock:
            return tuple(self._to_snapshot(circuit) for circuit in self._circuits.values())

    def tracked_jobs(self) -> Tuple[str, ...]:
        """列出当前持有熔断记录的作业标识。

        :return: 作业标识元组
        """
        with self._lock:
            return tuple(self._circuits)

    def reset(self, job_id: str) -> None:
        """复位单条作业的熔断状态，使其立即恢复调度。

        :param job_id: 作业标识
        :return: 无返回值
        """
        self.discard((job_id,))

    def discard(self, job_ids: Iterable[str]) -> None:
        """丢弃若干作业的熔断记录。

        :param job_ids: 作业标识集合
        :return: 无返回值
        """
        with self._lock:
            for job_id in job_ids:
                self._circuits.pop(job_id, None)

    def clear(self) -> None:
        """丢弃全部熔断记录。

        :return: 无返回值
        """
        with self._lock:
            self._circuits.clear()

    @staticmethod
    def _trip(circuit: _Circuit, now: float) -> None:
        """把记录切到打开状态并从当前时刻重新计时恢复间隔。

        :param circuit: 熔断记录
        :param now: 跳闸时刻
        :return: 无返回值
        """
        circuit.state = CircuitState.OPEN
        circuit.opened_at = now
        circuit.trip_count += 1

    @staticmethod
    def _describe(
        circuit: _Circuit,
        job_name: Optional[str],
        plugin_id: Optional[str],
    ) -> None:
        """把最新的作业显示名与插件标识补进记录。

        :param circuit: 熔断记录
        :param job_name: 作业显示名
        :param plugin_id: 作业所属插件标识
        :return: 无返回值
        """
        if job_name:
            circuit.job_name = job_name
        if plugin_id:
            circuit.plugin_id = plugin_id

    @staticmethod
    def _describe_job(circuit: _Circuit) -> str:
        """拼接熔断记录在日志中的点名描述。

        :param circuit: 熔断记录
        :return: 点名描述
        """
        return describe_job(circuit.job_id, circuit.job_name, circuit.plugin_id)

    def _to_snapshot(self, circuit: _Circuit) -> CircuitSnapshot:
        """按熔断记录生成只读快照。

        :param circuit: 熔断记录
        :return: 熔断快照
        """
        threshold = self._threshold_provider()
        return CircuitSnapshot(
            job_id=circuit.job_id,
            job_name=circuit.job_name,
            plugin_id=circuit.plugin_id,
            state=circuit.state,
            consecutive_failures=circuit.consecutive_failures,
            threshold=threshold,
            degraded=circuit.consecutive_failures >= threshold,
            enforced=self._enabled_provider(),
            last_error=circuit.last_error,
            skipped_runs=circuit.skipped_runs,
            trip_count=circuit.trip_count,
        )
