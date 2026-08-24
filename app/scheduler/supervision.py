"""定时作业的执行观测接入：把看门狗与插件作业熔断挂到作业分发路径上。

观测挂在作业函数外层而不是调度器作业事件上：调度器只在作业函数返回后才发事件，
而协程作业在提交到事件循环后就立即返回，且执行引擎自己吞掉了作业异常——两者
都让作业事件既测不准时长也看不到成败。作业函数外层包一层则对同步与协程作业
都在真实收口时刻拿到结果。

包装在首次触发时按作业标识就地完成并做幂等标记：作业登记有宿主清单、工作流、
Agent 任务与插件四条来源，在分发口统一包装可覆盖全部来源且不重复套壳。
"""

from __future__ import annotations

import functools
import inspect
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from app.runtime.extensions.contract.instance import extension_id_of
from app.runtime.log import logger
from app.scheduler.breaker import CircuitSnapshot, JobCircuitBreaker
from app.scheduler.watchdog import JobWatchdog, RunningJobSnapshot, describe_job

# 作业函数已包裹观测的标记属性名
SUPERVISED_FLAG = "__moviepilot_job_supervised__"


@dataclass(frozen=True, slots=True)
class JobContext:
    """一条作业在观测中使用的归属信息。

    :param job_id: 作业标识
    :param job_name: 作业显示名
    :param provider_name: 作业提供方显示名
    :param plugin_id: 插件作业所属插件标识，非插件作业为 None
    """

    job_id: str
    job_name: Optional[str]
    provider_name: Optional[str]
    plugin_id: Optional[str]


def failure_text(result: Any) -> Optional[str]:
    """从作业标准失败返回值中提取失败原因。

    :param result: 作业返回值
    :return: 失败原因，成功时返回 None
    """
    if (
        isinstance(result, tuple)
        and result
        and isinstance(result[0], bool)
        and result[0] is False
    ):
        return str(result[1]) if len(result) > 1 and result[1] else "定时任务返回失败"
    return None


def error_text(error: BaseException) -> str:
    """把作业异常转成失败原因文本。

    :param error: 作业抛出的异常
    :return: 失败原因
    """
    return str(error) or error.__class__.__name__


class JobSupervision:
    """在作业分发路径上接入执行时长观测与插件作业熔断。"""

    # 观测组件按调度器实例惰性创建，不依赖调度器的构造路径
    _job_watchdog: Optional[JobWatchdog] = None
    _job_breaker: Optional[JobCircuitBreaker] = None
    _job_supervision_lock = threading.Lock()

    @property
    def job_watchdog(self) -> JobWatchdog:
        """取作业看门狗，首次访问时创建。

        :return: 看门狗实例
        """
        if self._job_watchdog is None:
            with JobSupervision._job_supervision_lock:
                if self._job_watchdog is None:
                    self._job_watchdog = JobWatchdog()
        return self._job_watchdog

    @property
    def job_breaker(self) -> JobCircuitBreaker:
        """取插件作业熔断器，首次访问时创建。

        :return: 熔断器实例
        """
        if self._job_breaker is None:
            with JobSupervision._job_supervision_lock:
                if self._job_breaker is None:
                    self._job_breaker = JobCircuitBreaker()
        return self._job_breaker

    def start(self, job_id: str, *args, **kwargs) -> None:
        """在作业分发前后接入熔断判定与执行观测。

        :param job_id: 作业标识
        :return: 无返回值
        """
        context = self.job_context(job_id)
        if context.plugin_id and not self.job_breaker.allow(
            job_id, job_name=context.job_name, plugin_id=context.plugin_id
        ):
            return
        self._supervise_job_func(job_id)
        super().start(job_id, *args, **kwargs)

    def job_context(self, job_id: str) -> JobContext:
        """取作业当前的归属信息。

        :param job_id: 作业标识
        :return: 作业归属信息，作业未登记时各字段为空
        """
        with self._lock:
            job = self._jobs.get(job_id) or {}
            owner = job.get("pid")
            return JobContext(
                job_id=job_id,
                job_name=job.get("name"),
                provider_name=job.get("provider_name"),
                plugin_id=extension_id_of(owner) if owner else None,
            )

    def list_running_jobs(self) -> Tuple[RunningJobSnapshot, ...]:
        """列出当前在途的作业执行。

        :return: 在途作业快照元组
        """
        return self.job_watchdog.running_jobs()

    def list_job_circuits(self) -> Tuple[CircuitSnapshot, ...]:
        """列出当前持有故障记录的插件作业熔断状态。

        :return: 熔断快照元组
        """
        return self.job_breaker.snapshots()

    def list_job_misfires(self) -> Dict[str, int]:
        """列出各作业累计错过触发的次数。

        :return: 作业标识到次数的映射
        """
        return self.job_watchdog.misfires()

    def reset_job_circuit(self, job_id: str) -> None:
        """复位单条作业的熔断状态，使其立即恢复调度。

        :param job_id: 作业标识
        :return: 无返回值
        """
        self.job_breaker.reset(job_id)

    def discard_job_circuits(self, job_ids: Iterable[str]) -> None:
        """丢弃若干作业的熔断记录。

        :param job_ids: 作业标识集合
        :return: 无返回值
        """
        self.job_breaker.discard(job_ids)

    def on_job_missed(self, event: Any) -> None:
        """记录调度器错过触发的作业。

        错过触发意味着作业在 `misfire_grace_time` 内没能被执行线程取走，
        本次触发被整体跳过，因此需要单独计数与告警。
        :param event: 调度器作业事件
        :return: 无返回值
        """
        job_id = str(getattr(event, "job_id", "") or "").split("|")[0]
        if not job_id:
            return
        context = self.job_context(job_id)
        counted = self.job_watchdog.record_misfire(job_id)
        logger.warning(
            f"定时作业 {describe_job(job_id, context.job_name, context.plugin_id)} "
            f"错过本次触发，未在容忍时间内被执行线程取走（累计 {counted} 次）"
        )

    def _supervise_job_func(self, job_id: str) -> None:
        """把作业函数替换为带执行观测的等价函数。

        :param job_id: 作业标识
        :return: 无返回值
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            func = job.get("func")
            if not callable(func) or getattr(func, SUPERVISED_FLAG, False):
                return
            job["func"] = self._wrap_job_func(job_id, func)

    def _wrap_job_func(self, job_id: str, func: Callable[..., Any]) -> Callable[..., Any]:
        """给作业函数包一层执行观测，保持签名与协程性不变。

        :param job_id: 作业标识
        :param func: 原作业函数
        :return: 带观测的等价函数
        """
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def supervised(*args, **kwargs):
                """执行协程作业并在真实收口时记录结果。"""
                token = self._begin_job_run(job_id)
                try:
                    result = await func(*args, **kwargs)
                except BaseException as err:
                    self._finish_job_run(job_id, token, error=error_text(err))
                    raise
                self._finish_job_run(job_id, token, error=failure_text(result))
                return result
        else:
            @functools.wraps(func)
            def supervised(*args, **kwargs):
                """执行同步作业并在返回时记录结果。"""
                token = self._begin_job_run(job_id)
                try:
                    result = func(*args, **kwargs)
                except BaseException as err:
                    self._finish_job_run(job_id, token, error=error_text(err))
                    raise
                self._finish_job_run(job_id, token, error=failure_text(result))
                return result

        setattr(supervised, SUPERVISED_FLAG, True)
        return supervised

    def _begin_job_run(self, job_id: str) -> int:
        """登记一次作业执行的开始。

        :param job_id: 作业标识
        :return: 本次执行的登记令牌
        """
        context = self.job_context(job_id)
        return self.job_watchdog.begin(
            job_id,
            job_name=context.job_name,
            plugin_id=context.plugin_id,
            provider_name=context.provider_name,
        )

    def _finish_job_run(self, job_id: str, token: int, error: Optional[str]) -> None:
        """收敛一次作业执行的观测结果。

        :param job_id: 作业标识
        :param token: 本次执行的登记令牌
        :param error: 失败原因，成功时为 None
        :return: 无返回值
        """
        outcome = self.job_watchdog.end(token)
        context = self.job_context(job_id)
        described = describe_job(job_id, context.job_name, context.plugin_id)
        if outcome.overdue:
            logger.warning(
                f"定时作业 {described} 本次执行耗时 {outcome.elapsed_seconds:.0f} 秒，"
                f"超过看门狗阈值 {self.job_watchdog.overdue_seconds():.0f} 秒"
            )
        if not context.plugin_id:
            return
        if error:
            reason = error
        elif outcome.overdue:
            reason = f"执行超时 {outcome.elapsed_seconds:.0f} 秒"
        else:
            self.job_breaker.record_success(
                job_id, job_name=context.job_name, plugin_id=context.plugin_id
            )
            return
        self.job_breaker.record_failure(
            job_id,
            reason=reason,
            job_name=context.job_name,
            plugin_id=context.plugin_id,
        )
