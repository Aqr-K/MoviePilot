"""事件循环延迟探针与阻塞检测器的采样、统计和插件归因行为。"""

import threading
import time
import traceback
import types

from app.runtime.diagnostics import blocking, loop_probe


def _frame_summary(filename: str, lineno: int, name: str) -> traceback.FrameSummary:
    return traceback.FrameSummary(filename, lineno, name)


def _make_function_with_filename(func, filename):
    """构造一个函数，其代码对象文件名替换为 filename，模拟栈帧来自某插件文件。"""
    code = func.__code__.replace(co_filename=filename)
    return types.FunctionType(
        code, func.__globals__, func.__name__, func.__defaults__, func.__closure__
    )


# ==================== 事件循环延迟探针 ====================


def test_probe_measures_delay_when_event_loop_is_blocked():
    """协程内的同步 time.sleep 会顶住事件循环，探针必须测得接近阻塞时长的延迟。"""
    import asyncio

    async def scenario():
        probe = loop_probe.EventLoopLatencyProbe(
            interval_seconds=0.05,
            window_size=10,
            warn_threshold_seconds=0.2,
        )
        probe.start()
        try:
            await asyncio.sleep(0.02)
            # 在事件循环线程内直接同步阻塞，模拟真阻塞场景（而非线程饥饿）。
            time.sleep(0.35)
            await asyncio.sleep(0.05)
        finally:
            await probe.stop()
        return probe.snapshot()

    snapshot = asyncio.run(scenario())

    assert snapshot.max_seconds >= 0.2
    assert snapshot.exceeded_threshold is True


def test_probe_does_not_report_false_positive_when_idle():
    """事件循环空闲、无阻塞时，采样延迟应保持在阈值以下。"""
    import asyncio

    async def scenario():
        probe = loop_probe.EventLoopLatencyProbe(
            interval_seconds=0.05,
            window_size=20,
            warn_threshold_seconds=0.2,
        )
        probe.start()
        try:
            await asyncio.sleep(0.3)
        finally:
            await probe.stop()
        return probe.snapshot()

    snapshot = asyncio.run(scenario())

    assert snapshot.sample_count > 0
    assert snapshot.exceeded_threshold is False
    assert snapshot.max_seconds < 0.2


def test_snapshot_reports_percentiles_and_threshold():
    """滑动窗口统计需要暴露样本数、p50/p95/max 与阈值判定。"""
    probe = loop_probe.EventLoopLatencyProbe(
        interval_seconds=0.01,
        window_size=5,
        warn_threshold_seconds=0.05,
    )
    for value in (0.01, 0.02, 0.03, 0.04, 0.05):
        probe._record(value)

    snapshot = probe.snapshot()

    assert snapshot.sample_count == 5
    assert snapshot.last_seconds == 0.05
    assert snapshot.threshold_seconds == 0.05
    assert snapshot.max_seconds == 0.05
    assert snapshot.p50_seconds in (0.02, 0.03)
    assert snapshot.exceeded_threshold is True


def test_empty_snapshot_reports_zero_without_dividing_by_sample_count():
    """未采样时快照应返回零值而非抛异常。"""
    probe = loop_probe.EventLoopLatencyProbe(
        interval_seconds=0.5, window_size=5, warn_threshold_seconds=0.2
    )

    snapshot = probe.snapshot()

    assert snapshot.sample_count == 0
    assert snapshot.exceeded_threshold is False


def test_probe_logs_warning_when_latency_exceeds_threshold(monkeypatch):
    """单次采样延迟超过阈值必须记 WARNING 日志。"""
    warnings = []
    monkeypatch.setattr(
        loop_probe.logger, "warning", lambda *args, **kwargs: warnings.append(args)
    )
    probe = loop_probe.EventLoopLatencyProbe(
        interval_seconds=0.01, window_size=5, warn_threshold_seconds=0.05
    )

    probe._record(0.1)

    assert warnings, "延迟超过阈值时必须记录 WARNING 日志"


def test_probe_does_not_log_warning_below_threshold(monkeypatch):
    """阈值以下的采样不应记 WARNING 日志。"""
    warnings = []
    monkeypatch.setattr(
        loop_probe.logger, "warning", lambda *args, **kwargs: warnings.append(args)
    )
    probe = loop_probe.EventLoopLatencyProbe(
        interval_seconds=0.01, window_size=5, warn_threshold_seconds=0.05
    )

    probe._record(0.01)

    assert not warnings


def test_stop_cancels_background_task_cleanly():
    """stop 必须取消后台任务并清空任务引用。"""
    import asyncio

    async def scenario():
        probe = loop_probe.EventLoopLatencyProbe(
            interval_seconds=0.5, window_size=5, warn_threshold_seconds=0.2
        )
        probe.start()
        await asyncio.sleep(0)
        await probe.stop()
        return probe._task

    task = asyncio.run(scenario())
    assert task is None


def test_probe_start_is_idempotent():
    """重复调用 start 不应创建第二个后台任务。"""
    import asyncio

    async def scenario():
        probe = loop_probe.EventLoopLatencyProbe(
            interval_seconds=0.5, window_size=5, warn_threshold_seconds=0.2
        )
        probe.start()
        first_task = probe._task
        probe.start()
        second_task = probe._task
        await probe.stop()
        return first_task is second_task

    assert asyncio.run(scenario()) is True


def test_start_loop_latency_probe_configures_slow_callback_duration(monkeypatch):
    """进程级启动函数需要按配置对齐 asyncio 慢回调阈值，并注册为可查询单例。"""
    import asyncio

    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_ENABLE", True)
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_INTERVAL_SECONDS", 1.0)
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_WINDOW_SIZE", 10)
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_WARN_THRESHOLD_SECONDS", 0.2)
    monkeypatch.setattr(loop_probe.settings, "LOOP_SLOW_CALLBACK_DURATION_SECONDS", 0.33)

    async def scenario():
        probe = loop_probe.start_loop_latency_probe()
        try:
            assert probe is not None
            assert asyncio.get_event_loop().slow_callback_duration == 0.33
            assert loop_probe.get_loop_latency_probe() is probe
        finally:
            await loop_probe.stop_loop_latency_probe()

    asyncio.run(scenario())
    assert loop_probe.get_loop_latency_probe() is None


def test_start_loop_latency_probe_disabled_by_config(monkeypatch):
    """探针总开关关闭时不应创建或暴露任何实例。"""
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_ENABLE", False)

    probe = loop_probe.start_loop_latency_probe()

    assert probe is None
    assert loop_probe.get_loop_latency_probe() is None


# ==================== 阻塞检测：当前线程判定 + 栈帧归因 ====================


def test_attribute_plugin_from_stack_finds_plugin_frame():
    """归因需在多层调用栈中找到属于插件包路径的帧。"""
    stack = [
        _frame_summary("/opt/app/main.py", 10, "run"),
        _frame_summary("/opt/app/app/plugins/demo_plugin/entry.py", 42, "sync_call"),
        _frame_summary("/usr/lib/python3.12/socket.py", 700, "connect"),
    ]

    attribution = blocking.attribute_plugin_from_stack(stack)

    assert attribution is not None
    assert attribution.plugin_id == "demo_plugin"
    assert attribution.file.endswith("entry.py")
    assert attribution.line == 42
    assert attribution.function == "sync_call"


def test_attribute_plugin_from_stack_prefers_innermost_plugin_frame():
    """多插件互相调用时，归因应指向离阻塞点最近（最内层）的插件帧。"""
    stack = [
        _frame_summary("/opt/app/app/plugins/outer_plugin/entry.py", 5, "call_other"),
        _frame_summary("/opt/app/app/plugins/inner_plugin/worker.py", 88, "do_block"),
    ]

    attribution = blocking.attribute_plugin_from_stack(stack)

    assert attribution.plugin_id == "inner_plugin"


def test_attribute_plugin_from_stack_returns_none_without_plugin_frame():
    """栈里完全没有插件代码时必须返回 None，不能误报。"""
    stack = [
        _frame_summary("/opt/app/app/runtime/log.py", 1, "emit"),
        _frame_summary("/usr/lib/python3.12/asyncio/base_events.py", 200, "_run_once"),
    ]

    assert blocking.attribute_plugin_from_stack(stack) is None


def test_attribute_plugin_from_stack_supports_versioned_layout():
    """按版本分目录后的路径形如 app/plugins/<pid>/<版本号>/xxx.py，插件 ID 仍是第三段。"""
    stack = [
        _frame_summary("/opt/app/app/plugins/demo_plugin/1.2.0/entry.py", 7, "handler"),
    ]

    attribution = blocking.attribute_plugin_from_stack(stack)

    assert attribution.plugin_id == "demo_plugin"


def test_is_running_in_event_loop_thread_tracks_recorded_thread():
    """记录当前线程为事件循环线程后，仅该线程判定为 True，其余线程为 False。"""
    blocking.record_event_loop_thread()
    assert blocking.is_running_in_event_loop_thread() is True

    result = {}

    def probe():
        result["value"] = blocking.is_running_in_event_loop_thread()

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join()

    assert result["value"] is False


def test_attribute_plugin_from_thread_frame_reads_live_stack_of_target_thread():
    """从指定线程的当前挂起帧向上回溯，命中真实运行中的插件文件路径。"""
    ready = threading.Event()
    release = threading.Event()

    def _blocking_body():
        ready.set()
        release.wait(timeout=2)

    plugin_path = "/opt/app/app/plugins/demo_plugin/entry.py"
    target = _make_function_with_filename(_blocking_body, plugin_path)

    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert ready.wait(timeout=2)
        attribution = blocking.attribute_plugin_from_thread_frame(thread.ident)
        assert attribution is not None
        assert attribution.plugin_id == "demo_plugin"
    finally:
        release.set()
        thread.join(timeout=2)


def test_attribute_plugin_from_thread_frame_returns_none_for_unknown_thread():
    """未知线程 ID（已退出或不存在）必须安全返回 None。"""
    assert blocking.attribute_plugin_from_thread_frame(-1) is None


# ==================== 阻塞检测：独立采样线程 ====================


def test_watchdog_captures_attribution_from_blocked_event_loop_thread():
    """采样线程独立于被观测线程运行，能在阻塞发生期间捕获插件归因。"""
    ready = threading.Event()
    release = threading.Event()

    def _blocking_body():
        ready.set()
        release.wait(timeout=2)

    plugin_path = "/opt/app/app/plugins/culprit_plugin/worker.py"
    target = _make_function_with_filename(_blocking_body, plugin_path)

    loop_thread = threading.Thread(target=target)
    loop_thread.start()
    watchdog = blocking.EventLoopBlockingWatchdog(sample_interval_seconds=0.02)
    try:
        assert ready.wait(timeout=2)
        watchdog.start(loop_thread.ident)
        deadline = time.monotonic() + 2
        attribution = None
        while time.monotonic() < deadline:
            attribution = watchdog.last_plugin_attribution()
            if attribution is not None:
                break
            time.sleep(0.02)
        assert attribution is not None
        assert attribution.plugin_id == "culprit_plugin"
    finally:
        release.set()
        loop_thread.join(timeout=2)
        watchdog.stop()


def test_watchdog_attribution_since_ignores_samples_before_cutoff():
    """attribution_since 只应返回给定时间点之后的命中，早于该时间点的历史命中必须被忽略。"""
    watchdog = blocking.EventLoopBlockingWatchdog(sample_interval_seconds=10)
    old_hit = blocking.PluginStackAttribution(
        plugin_id="stale_plugin", file="stale.py", line=1, function="f"
    )
    watchdog._history.append((time.monotonic() - 100, old_hit))

    assert watchdog.attribution_since(time.monotonic() - 1) is None
    assert watchdog.attribution_since(time.monotonic() - 200) is old_hit


def test_watchdog_start_stop_is_idempotent_and_joins_thread():
    """重复 start/stop 不应重复起线程或报错。"""
    watchdog = blocking.EventLoopBlockingWatchdog(sample_interval_seconds=0.01)
    watchdog.start(threading.get_ident())
    watchdog.start(threading.get_ident())
    watchdog.stop()
    watchdog.stop()
