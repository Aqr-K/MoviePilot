"""定时作业看门狗与插件作业熔断。

两者共用同一条作业分发路径上的观测：

- 看门狗记录每次作业的墙钟执行时长，对「仍在运行且已超时」的作业点名告警，
  但绝不终止作业——Python 没有安全终止线程的手段，强杀会留下不一致状态；
- 熔断只对插件定时作业生效，且作用域是单条作业而不是整个插件，一条定时任务
  连续失败不代表该插件提供的 API、页面与事件处理都该停。
"""

import asyncio
import threading
import time
from datetime import datetime
from typing import List
from uuid import uuid4

import pytest
from apscheduler.events import EVENT_JOB_MISSED, JobExecutionEvent

from app.scheduler import Scheduler
from app.scheduler import composition as composition_module
from app.scheduler.breaker import CircuitState, JobCircuitBreaker
from app.scheduler.watchdog import JobWatchdog


class _Clock:
    """可手动推进的单调时钟，避免用例依赖真实等待时长。"""

    def __init__(self, start: float = 1000.0) -> None:
        """
        :param start: 初始读数
        """
        self.now = start

    def __call__(self) -> float:
        """读取当前时间。"""
        return self.now

    def advance(self, seconds: float) -> None:
        """推进时间。

        :param seconds: 推进秒数
        """
        self.now += seconds


@pytest.fixture(name="watchdogs")
def fixture_watchdogs():
    """构造看门狗并在用例结束后停止其采样线程。"""
    created: List[JobWatchdog] = []

    def _factory(
            clock: _Clock,
            *,
            enabled: bool = True,
            overdue: float = 30.0,
            interval: float = 3600.0,
    ) -> JobWatchdog:
        watchdog = JobWatchdog(
            enabled_provider=lambda: enabled,
            overdue_provider=lambda: overdue,
            interval_provider=lambda: interval,
            clock=clock,
        )
        created.append(watchdog)
        return watchdog

    yield _factory
    for watchdog in created:
        watchdog.stop()


def _breaker(
        clock: _Clock,
        *,
        enabled: bool = True,
        threshold: int = 3,
        window: float = 600.0,
        recovery: float = 60.0,
) -> JobCircuitBreaker:
    """构造固定阈值的熔断器。"""
    return JobCircuitBreaker(
        enabled_provider=lambda: enabled,
        threshold_provider=lambda: threshold,
        window_provider=lambda: window,
        recovery_provider=lambda: recovery,
        clock=clock,
    )


def _build_scheduler(jobs: dict) -> Scheduler:
    """构造不启动 APScheduler 的定时服务测试对象。"""
    scheduler = object.__new__(Scheduler)
    scheduler._lock = threading.RLock()
    scheduler._jobs = jobs
    scheduler._scheduler = None
    return scheduler


def _plugin_job(func, *, name: str = "演示同步") -> dict:
    """构造一条插件定时作业的运行状态登记。"""
    return {
        "name": name,
        "func": func,
        "pid": "DemoPlugin@second",
        "provider_name": "演示插件",
        "running": False,
    }


# --------------------------------------------------------------------------- #
# 作业墙钟看门狗
# --------------------------------------------------------------------------- #

def test_watchdog_names_overdue_running_job_before_it_finishes(watchdogs):
    """作业尚未结束就已超时时必须点名作业与所属插件，这正是 APScheduler 作业事件看不到的状态。"""
    clock = _Clock()
    watchdog = watchdogs(clock, overdue=30.0)

    watchdog.begin(
        "DemoPlugin@second_sync",
        job_name="演示同步",
        plugin_id="DemoPlugin",
        provider_name="演示插件",
    )
    clock.advance(31.0)
    overdue = watchdog.overdue_jobs()

    assert len(overdue) == 1
    assert overdue[0].job_id == "DemoPlugin@second_sync"
    assert overdue[0].job_name == "演示同步"
    assert overdue[0].plugin_id == "DemoPlugin"
    assert overdue[0].elapsed_seconds == pytest.approx(31.0)


def test_watchdog_warns_once_per_overdue_run(watchdogs, monkeypatch):
    """同一次超时执行只告警一次，长时间挂起的作业不得刷屏。"""
    clock = _Clock()
    watchdog = watchdogs(clock, overdue=30.0)
    warnings: List[str] = []
    monkeypatch.setattr(
        "app.scheduler.watchdog.logger.warning", lambda message: warnings.append(message)
    )

    watchdog.begin("host_job", job_name="宿主作业")
    clock.advance(31.0)
    watchdog.sample()
    clock.advance(31.0)
    watchdog.sample()

    assert len(warnings) == 1
    assert "宿主作业" in warnings[0]


def test_watchdog_drops_inflight_entry_when_run_ends(watchdogs):
    """作业结束后必须摘掉在途记录，在途表不随作业次数增长。"""
    clock = _Clock()
    watchdog = watchdogs(clock, overdue=30.0)

    token = watchdog.begin("host_job", job_name="宿主作业")
    clock.advance(45.0)
    outcome = watchdog.end(token)

    assert outcome.elapsed_seconds == pytest.approx(45.0)
    assert outcome.overdue is True
    assert watchdog.running_jobs() == ()


def test_watchdog_disabled_reports_no_overdue(watchdogs):
    """看门狗关闭后不再判定超时。"""
    clock = _Clock()
    watchdog = watchdogs(clock, enabled=False, overdue=1.0)

    token = watchdog.begin("host_job", job_name="宿主作业")
    clock.advance(600.0)

    assert watchdog.overdue_jobs() == ()
    assert watchdog.end(token).overdue is False


def test_watchdog_sampler_thread_starts_on_demand_and_exits_when_idle(watchdogs):
    """采样线程随作业开始按需启动，作业收口后自行退出，不常驻空转。"""
    clock = _Clock()
    watchdog = watchdogs(clock, overdue=0.0, interval=0.01)

    token = watchdog.begin("host_job", job_name="宿主作业")
    deadline = time.monotonic() + 5
    while not watchdog.sampler_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert watchdog.sampler_alive() is True

    watchdog.end(token)
    deadline = time.monotonic() + 5
    while watchdog.sampler_alive() and time.monotonic() < deadline:
        time.sleep(0.01)

    assert watchdog.sampler_alive() is False


def test_watchdog_counts_misfires_per_job(watchdogs):
    """错过触发的次数按作业累计，供评估 misfire_grace_time 是否过紧。"""
    clock = _Clock()
    watchdog = watchdogs(clock)

    assert watchdog.record_misfire("host_job") == 1
    assert watchdog.record_misfire("host_job") == 2

    assert watchdog.misfires() == {"host_job": 2}


# --------------------------------------------------------------------------- #
# 熔断状态机
# --------------------------------------------------------------------------- #

def test_breaker_allows_job_without_record():
    """没有故障记录的作业直接放行，也不因一次放行就建记录。"""
    breaker = _breaker(_Clock())

    assert breaker.allow("DemoPlugin_sync") is True
    assert breaker.tracked_jobs() == ()


def test_breaker_stays_closed_below_threshold():
    """未达连续失败阈值不得跳闸，偶发抖动不能误伤插件。"""
    breaker = _breaker(_Clock(), threshold=3)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="网络超时")

    snapshot = breaker.snapshot("DemoPlugin_sync")
    assert snapshot.state is CircuitState.CLOSED
    assert snapshot.consecutive_failures == 2
    assert breaker.allow("DemoPlugin_sync") is True


def test_breaker_opens_after_consecutive_failures(monkeypatch):
    """连续失败达阈值后跳闸，并记 WARNING 点名作业与插件。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=3)
    warnings: List[str] = []
    monkeypatch.setattr(
        "app.scheduler.breaker.logger.warning", lambda message: warnings.append(message)
    )

    for _ in range(3):
        breaker.record_failure(
            "DemoPlugin@second_sync",
            reason="连接被拒绝",
            job_name="演示同步",
            plugin_id="DemoPlugin",
        )

    snapshot = breaker.snapshot("DemoPlugin@second_sync")
    assert snapshot.state is CircuitState.OPEN
    assert snapshot.trip_count == 1
    assert warnings
    assert "DemoPlugin" in warnings[-1]
    assert "演示同步" in warnings[-1]


def test_breaker_skips_execution_while_open():
    """跳闸后在恢复间隔内一律不放行，并累计跳过次数。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=2, recovery=60.0)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="失败")

    assert breaker.allow("DemoPlugin_sync") is False
    clock.advance(59.0)
    assert breaker.allow("DemoPlugin_sync") is False
    assert breaker.snapshot("DemoPlugin_sync").skipped_runs == 2


def test_breaker_half_opens_after_recovery_delay_and_probes_once():
    """恢复间隔到期后只放行一次试探，试探在途期间不得再次放行。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=2, recovery=60.0)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="失败")
    clock.advance(60.0)

    assert breaker.allow("DemoPlugin_sync") is True
    assert breaker.snapshot("DemoPlugin_sync").state is CircuitState.HALF_OPEN
    assert breaker.allow("DemoPlugin_sync") is False


def test_breaker_closes_after_successful_probe():
    """半开试探成功即闭合，作业恢复正常调度。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=2, recovery=60.0)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="失败")
    clock.advance(60.0)
    breaker.allow("DemoPlugin_sync")
    breaker.record_success("DemoPlugin_sync")

    assert breaker.snapshot("DemoPlugin_sync") is None
    assert breaker.allow("DemoPlugin_sync") is True


def test_breaker_reopens_after_failed_probe():
    """半开试探失败立即退回打开，并从失败时刻重新计时恢复间隔。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=2, recovery=60.0)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="失败")
    clock.advance(60.0)
    breaker.allow("DemoPlugin_sync")
    breaker.record_failure("DemoPlugin_sync", reason="仍然失败")

    assert breaker.snapshot("DemoPlugin_sync").state is CircuitState.OPEN
    assert breaker.allow("DemoPlugin_sync") is False
    clock.advance(60.0)
    assert breaker.allow("DemoPlugin_sync") is True


def test_breaker_resets_streak_when_failures_are_far_apart():
    """两次失败相隔超过窗口即视为互不相关，连续计数归零。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=3, window=600.0)

    breaker.record_failure("DemoPlugin_sync", reason="失败")
    breaker.record_failure("DemoPlugin_sync", reason="失败")
    clock.advance(601.0)
    breaker.record_failure("DemoPlugin_sync", reason="失败")

    snapshot = breaker.snapshot("DemoPlugin_sync")
    assert snapshot.consecutive_failures == 1
    assert snapshot.state is CircuitState.CLOSED


def test_breaker_success_drops_record():
    """成功一次即清空故障记录，映射只保留有故障的作业。"""
    breaker = _breaker(_Clock(), threshold=3)

    breaker.record_failure("DemoPlugin_sync", reason="失败")
    assert breaker.tracked_jobs() == ("DemoPlugin_sync",)

    breaker.record_success("DemoPlugin_sync")

    assert breaker.tracked_jobs() == ()


def test_breaker_disabled_warns_without_skipping(monkeypatch):
    """熔断未启用时只按同一阈值点名告警，绝不跳过任何一次执行。"""
    breaker = _breaker(_Clock(), enabled=False, threshold=3)
    warnings: List[str] = []
    monkeypatch.setattr(
        "app.scheduler.breaker.logger.warning", lambda message: warnings.append(message)
    )

    for _ in range(3):
        breaker.record_failure(
            "DemoPlugin_sync",
            reason="失败",
            job_name="演示同步",
            plugin_id="DemoPlugin",
        )

    snapshot = breaker.snapshot("DemoPlugin_sync")
    assert snapshot.state is CircuitState.CLOSED
    assert snapshot.degraded is True
    assert breaker.allow("DemoPlugin_sync") is True
    assert warnings
    assert "演示同步" in warnings[-1]


def test_breaker_discard_drops_record():
    """作业注销时丢弃其熔断记录，映射不随插件启停无界增长。"""
    breaker = _breaker(_Clock(), threshold=2)

    breaker.record_failure("DemoPlugin_sync", reason="失败")
    breaker.discard(["DemoPlugin_sync", "NotTracked_job"])

    assert breaker.tracked_jobs() == ()


def test_breaker_reset_returns_job_to_closed():
    """显式复位让跳闸的作业立即恢复调度，作为自动恢复之外的人工出口。"""
    clock = _Clock()
    breaker = _breaker(clock, threshold=2, recovery=3600.0)

    for _ in range(2):
        breaker.record_failure("DemoPlugin_sync", reason="失败")
    assert breaker.allow("DemoPlugin_sync") is False

    breaker.reset("DemoPlugin_sync")

    assert breaker.allow("DemoPlugin_sync") is True
    assert breaker.tracked_jobs() == ()


# --------------------------------------------------------------------------- #
# 接入作业分发路径
# --------------------------------------------------------------------------- #

def _install_supervision(scheduler: Scheduler, clock: _Clock, **kwargs) -> None:
    """给调度器装入固定时钟的看门狗与熔断器。"""
    scheduler._job_watchdog = JobWatchdog(
        enabled_provider=lambda: True,
        overdue_provider=lambda: kwargs.get("overdue", 30.0),
        interval_provider=lambda: 3600.0,
        clock=clock,
    )
    scheduler._job_breaker = _breaker(
        clock,
        enabled=kwargs.get("enabled", True),
        threshold=kwargs.get("threshold", 2),
        recovery=kwargs.get("recovery", 60.0),
    )


def test_scheduler_trips_circuit_for_failing_plugin_job(monkeypatch):
    """插件定时作业连续抛异常达阈值后跳闸。"""
    job_id = f"DemoPlugin@second_sync-{uuid4()}"

    def task():
        """总是失败的插件作业。"""
        raise RuntimeError("插件炸了")

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    monkeypatch.setattr(
        scheduler, "_SchedulerEngine__handle_job_error", lambda **kwargs: None
    )
    _install_supervision(scheduler, _Clock(), threshold=2)

    scheduler.start(job_id)
    scheduler.start(job_id)

    circuits = {item.job_id: item for item in scheduler.list_job_circuits()}
    assert circuits[job_id].state is CircuitState.OPEN
    assert circuits[job_id].plugin_id == "DemoPlugin"
    assert circuits[job_id].last_error == "插件炸了"


def test_scheduler_skips_plugin_job_while_circuit_open(monkeypatch):
    """跳闸期间不再调用插件作业函数，恢复间隔到期后放行一次试探并闭合。"""
    job_id = f"DemoPlugin@second_sync-{uuid4()}"
    calls: List[str] = []
    fail = {"value": True}

    def task():
        """按开关决定成败的插件作业。"""
        calls.append("run")
        if fail["value"]:
            raise RuntimeError("插件炸了")

    clock = _Clock()
    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    monkeypatch.setattr(
        scheduler, "_SchedulerEngine__handle_job_error", lambda **kwargs: None
    )
    _install_supervision(scheduler, clock, threshold=2, recovery=60.0)

    scheduler.start(job_id)
    scheduler.start(job_id)
    scheduler.start(job_id)
    assert len(calls) == 2

    clock.advance(60.0)
    fail["value"] = False
    scheduler.start(job_id)

    assert len(calls) == 3
    assert scheduler.list_job_circuits() == ()


def test_scheduler_does_not_trip_host_job(monkeypatch):
    """宿主作业不受熔断约束，熔断只是插件作业的降级手段。"""
    job_id = f"host-job-{uuid4()}"
    calls: List[str] = []

    def task():
        """总是失败的宿主作业。"""
        calls.append("run")
        raise RuntimeError("宿主作业失败")

    scheduler = _build_scheduler(
        {job_id: {"name": "宿主作业", "func": task, "running": False}}
    )
    monkeypatch.setattr(
        scheduler, "_SchedulerEngine__handle_job_error", lambda **kwargs: None
    )
    _install_supervision(scheduler, _Clock(), threshold=2)

    for _ in range(4):
        scheduler.start(job_id)

    assert len(calls) == 4
    assert scheduler.list_job_circuits() == ()


def test_scheduler_observes_async_plugin_job_failure(monkeypatch):
    """协程插件作业在真实结束后才收敛观测，不能因提前返回被判成功。"""
    job_id = f"DemoPlugin@second_async-{uuid4()}"

    async def task():
        """总是失败的协程插件作业。"""
        await asyncio.sleep(0)
        raise RuntimeError("协程炸了")

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    monkeypatch.setattr(
        scheduler, "_SchedulerEngine__handle_job_error", lambda **kwargs: None
    )
    _install_supervision(scheduler, _Clock(), threshold=2)

    scheduler.start(job_id)
    scheduler.start(job_id)

    circuits = {item.job_id: item for item in scheduler.list_job_circuits()}
    assert circuits[job_id].state is CircuitState.OPEN
    assert circuits[job_id].last_error == "协程炸了"


def test_scheduler_counts_tuple_failure_result_as_failure(monkeypatch):
    """返回 `(False, message)` 的插件作业与抛异常同样计入连续失败。"""
    job_id = f"DemoPlugin@second_sync-{uuid4()}"

    def task():
        """返回标准失败结果的插件作业。"""
        return False, "业务失败"

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    _install_supervision(scheduler, _Clock(), threshold=2)

    scheduler.start(job_id)
    scheduler.start(job_id)

    circuits = {item.job_id: item for item in scheduler.list_job_circuits()}
    assert circuits[job_id].state is CircuitState.OPEN
    assert circuits[job_id].last_error == "业务失败"


def test_scheduler_counts_overdue_run_as_failure():
    """执行超时的插件作业按失败计数，连续超时同样触发降级。"""
    job_id = f"DemoPlugin@second_slow-{uuid4()}"
    clock = _Clock()

    def task():
        """执行时长超过看门狗阈值的插件作业。"""
        clock.advance(31.0)

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    _install_supervision(scheduler, clock, threshold=2, overdue=30.0)

    scheduler.start(job_id)
    scheduler.start(job_id)

    circuits = {item.job_id: item for item in scheduler.list_job_circuits()}
    assert circuits[job_id].state is CircuitState.OPEN
    assert "超时" in circuits[job_id].last_error


def test_scheduler_wraps_job_func_once():
    """作业函数只包一层观测，反复触发不得层层套壳。"""
    job_id = f"DemoPlugin@second_sync-{uuid4()}"

    def task():
        """正常返回的插件作业。"""

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    _install_supervision(scheduler, _Clock())

    scheduler.start(job_id)
    wrapped = scheduler._jobs[job_id]["func"]
    scheduler.start(job_id)

    assert scheduler._jobs[job_id]["func"] is wrapped
    assert wrapped.__wrapped__ is task


def test_remove_plugin_job_discards_circuit(monkeypatch):
    """插件作业注销（含插件重载重注册）时清空其熔断记录。"""
    job_id = "DemoPlugin@second_sync"

    def task():
        """总是失败的插件作业。"""
        raise RuntimeError("插件炸了")

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    scheduler._scheduler = _SchedulerStub()
    monkeypatch.setattr(
        scheduler, "_SchedulerEngine__handle_job_error", lambda **kwargs: None
    )
    monkeypatch.setattr(
        "app.scheduler.plugins.PluginManager", lambda: _PluginManagerStub()
    )
    _install_supervision(scheduler, _Clock(), threshold=2)

    scheduler.start(job_id)
    scheduler.start(job_id)
    assert scheduler.list_job_circuits()

    scheduler.remove_plugin_job("DemoPlugin@second")

    assert scheduler.list_job_circuits() == ()


def test_scheduler_counts_missed_trigger():
    """错过触发按作业累计并点名，这一状态只有调度器事件看得到。"""
    job_id = "DemoPlugin@second_sync"

    def task():
        """从不被调用的插件作业。"""

    scheduler = _build_scheduler({job_id: _plugin_job(task)})
    _install_supervision(scheduler, _Clock())
    event = JobExecutionEvent(
        EVENT_JOB_MISSED,
        f"{job_id}|3:0",
        "default",
        datetime.now(),
    )

    scheduler.on_job_missed(event)
    scheduler.on_job_missed(event)

    assert scheduler.list_job_misfires() == {job_id: 2}


def test_scheduler_init_registers_missed_job_listener(monkeypatch):
    """调度器装配时必须挂上错过触发的事件监听，否则跳过的触发无人知晓。"""
    background = _BackgroundSchedulerStub()
    monkeypatch.setattr(composition_module, "BackgroundScheduler", lambda **_: background)
    monkeypatch.setattr(composition_module, "build_host_jobs", lambda **_: [])
    monkeypatch.setattr(composition_module.settings, "DEV", False)
    monkeypatch.setattr(composition_module.settings, "AI_AGENT_ENABLE", False)
    monkeypatch.setattr(Scheduler, "stop", lambda self: None)
    monkeypatch.setattr(Scheduler, "init_workflow_jobs", lambda self: None)
    monkeypatch.setattr(Scheduler, "init_plugin_jobs", lambda self: None)
    monkeypatch.setattr(
        Scheduler, "_reconcile_agent_task_interruptions", lambda self: None
    )
    scheduler = _build_scheduler({})
    scheduler._user_auth = _UserAuthStub()

    scheduler.init()

    assert background.listeners == [(scheduler.on_job_missed, EVENT_JOB_MISSED)]


class _BackgroundSchedulerStub:
    """记录事件监听登记的调度器替身。"""

    def __init__(self) -> None:
        """初始化监听登记表。"""
        self.listeners: List[tuple] = []

    def add_listener(self, callback, mask) -> None:
        """记录一次事件监听登记。"""
        self.listeners.append((callback, mask))

    def start(self) -> None:
        """忽略启动请求。"""


class _UserAuthStub:
    """只提供认证检查入口的作业替身。"""

    @staticmethod
    def check() -> None:
        """忽略认证检查。"""


class _SchedulerStub:
    """只提供作业查询与移除的调度器替身。"""

    def get_jobs(self) -> list:
        """返回空作业列表。"""
        return []

    def remove_job(self, job_id: str) -> None:
        """忽略移除请求。"""


class _PluginManagerStub:
    """只回答插件显示名的插件管理器替身。"""

    @staticmethod
    def get_plugin_attr(pid: str, attr: str) -> str:
        """返回插件显示名。"""
        return "演示插件"
