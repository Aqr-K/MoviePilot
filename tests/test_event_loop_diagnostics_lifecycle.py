"""事件循环诊断组件的生命周期装配契约，以及 doctor 诊断项对探针统计的暴露。"""

import asyncio

from fastapi import FastAPI

from app.doctor.models import DoctorFindingStatus, DoctorSeverity
from app.doctor.runner import DoctorRunner
from app.doctor import checks
from app.runtime.diagnostics import blocking, loop_probe
from app.startup import lifecycle


def test_lifecycle_manifest_includes_event_loop_diagnostics_between_thread_slot_and_database():
    """事件循环诊断必须早于数据库准备启动、晚于 HTTP 基础能力关闭，且正常/安全模式都启用。"""
    app = FastAPI()
    normal = lifecycle.get_lifecycle_manifest(app, safe_mode=False)
    safe = lifecycle.get_lifecycle_manifest(app, safe_mode=True)

    by_name = {item["name"]: item for item in normal}
    safe_names = {item["name"] for item in safe}

    assert "事件循环诊断" in by_name
    assert "事件循环诊断" in safe_names
    assert by_name["事件循环诊断"]["mode"] == "always"

    thread_slot_order = by_name["并发线程槽"]["start_order"]
    database_order = by_name["数据库准备"]["start_order"]
    diagnostics_start_order = by_name["事件循环诊断"]["start_order"]
    assert thread_slot_order < diagnostics_start_order < database_order

    http_stop_order = by_name["HTTP 基础能力"]["stop_order"]
    assert by_name["事件循环诊断"]["stop_order"] > http_stop_order


def test_start_and_stop_event_loop_diagnostics_wires_probe_and_watchdog(monkeypatch):
    """启动阶段必须同时装配延迟探针与阻塞采样线程，关闭阶段必须清空两者的进程内引用。"""
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_ENABLE", True)
    monkeypatch.setattr(blocking.settings, "LOOP_BLOCKING_DETECTOR_ENABLE", True)

    async def scenario():
        lifecycle.start_event_loop_diagnostics()
        try:
            assert loop_probe.get_loop_latency_probe() is not None
            assert blocking.get_event_loop_blocking_watchdog() is not None
            assert blocking.is_running_in_event_loop_thread() is True
        finally:
            await lifecycle.stop_event_loop_diagnostics()

        assert loop_probe.get_loop_latency_probe() is None
        assert blocking.get_event_loop_blocking_watchdog() is None

    asyncio.run(scenario())


def test_start_event_loop_diagnostics_respects_disabled_config(monkeypatch):
    """两个总开关关闭时，启动阶段不应创建任何探针或采样线程实例。"""
    monkeypatch.setattr(loop_probe.settings, "LOOP_LATENCY_PROBE_ENABLE", False)
    monkeypatch.setattr(blocking.settings, "LOOP_BLOCKING_DETECTOR_ENABLE", False)

    async def scenario():
        lifecycle.start_event_loop_diagnostics()
        try:
            assert loop_probe.get_loop_latency_probe() is None
            assert blocking.get_event_loop_blocking_watchdog() is None
        finally:
            await lifecycle.stop_event_loop_diagnostics()

    asyncio.run(scenario())


# ==================== doctor 诊断项 ====================


def test_doctor_check_skips_when_probe_not_running(monkeypatch):
    """探针未运行（如 CLI 独立诊断进程）时应给出可跳过的 Info 发现，不影响整体报告状态。"""
    monkeypatch.setattr(checks, "get_loop_latency_probe", lambda: None)

    runner = DoctorRunner()
    checks._check_event_loop_diagnostics(runner)

    finding = runner.report.find("runtime.event_loop_latency")
    assert finding is not None
    assert finding.status == DoctorFindingStatus.Skipped
    assert finding.affects_report_status is False


def test_doctor_check_reports_ok_when_latency_within_threshold(monkeypatch):
    """延迟未超阈值时应给出正常态 Info/Ok 发现。"""
    snapshot = loop_probe.LoopLatencySnapshot(
        sample_count=10,
        last_seconds=0.01,
        p50_seconds=0.01,
        p95_seconds=0.02,
        max_seconds=0.02,
        threshold_seconds=0.2,
        exceeded_threshold=False,
    )
    fake_probe = type("FakeProbe", (), {"snapshot": lambda self: snapshot})()
    monkeypatch.setattr(checks, "get_loop_latency_probe", lambda: fake_probe)

    runner = DoctorRunner()
    checks._check_event_loop_diagnostics(runner)

    finding = runner.report.find("runtime.event_loop_latency")
    assert finding is not None
    assert finding.status == DoctorFindingStatus.Ok
    assert finding.severity == DoctorSeverity.Info


def test_doctor_check_names_plugin_when_watchdog_attributes_blockage(monkeypatch):
    """延迟超标且采样线程命中插件帧时，建议必须点名具体插件。"""
    snapshot = loop_probe.LoopLatencySnapshot(
        sample_count=10,
        last_seconds=0.4,
        p50_seconds=0.1,
        p95_seconds=0.3,
        max_seconds=0.4,
        threshold_seconds=0.2,
        exceeded_threshold=True,
    )
    fake_probe = type("FakeProbe", (), {"snapshot": lambda self: snapshot})()
    monkeypatch.setattr(checks, "get_loop_latency_probe", lambda: fake_probe)

    attribution = blocking.PluginStackAttribution(
        plugin_id="culprit_plugin", file="/opt/app/app/plugins/culprit_plugin/worker.py",
        line=17, function="do_work",
    )
    fake_watchdog = type(
        "FakeWatchdog", (), {"attribution_since": lambda self, since: attribution}
    )()
    monkeypatch.setattr(checks, "get_event_loop_blocking_watchdog", lambda: fake_watchdog)

    runner = DoctorRunner()
    checks._check_event_loop_diagnostics(runner)

    finding = runner.report.find("runtime.event_loop_latency")
    assert finding is not None
    assert finding.status == DoctorFindingStatus.Degraded
    assert finding.severity == DoctorSeverity.Warn
    assert "culprit_plugin" in finding.title
    assert finding.context["plugin_id"] == "culprit_plugin"


def test_doctor_check_suspects_thread_starvation_when_no_plugin_found(monkeypatch):
    """延迟超标但采样线程栈中没有插件代码时，建议必须指向线程饥饿而非误判某个插件。"""
    snapshot = loop_probe.LoopLatencySnapshot(
        sample_count=10,
        last_seconds=0.4,
        p50_seconds=0.1,
        p95_seconds=0.3,
        max_seconds=0.4,
        threshold_seconds=0.2,
        exceeded_threshold=True,
    )
    fake_probe = type("FakeProbe", (), {"snapshot": lambda self: snapshot})()
    monkeypatch.setattr(checks, "get_loop_latency_probe", lambda: fake_probe)

    fake_watchdog = type(
        "FakeWatchdog", (), {"attribution_since": lambda self, since: None}
    )()
    monkeypatch.setattr(checks, "get_event_loop_blocking_watchdog", lambda: fake_watchdog)

    runner = DoctorRunner()
    checks._check_event_loop_diagnostics(runner)

    finding = runner.report.find("runtime.event_loop_latency")
    assert finding is not None
    assert finding.status == DoctorFindingStatus.Degraded
    assert "线程" in finding.recommendation
    assert "plugin_id" not in finding.context


def test_doctor_check_handles_missing_watchdog_gracefully(monkeypatch):
    """阻塞检测总开关关闭、watchdog 不存在时，延迟超标仍要给出线程饥饿方向的发现而不报错。"""
    snapshot = loop_probe.LoopLatencySnapshot(
        sample_count=10,
        last_seconds=0.4,
        p50_seconds=0.1,
        p95_seconds=0.3,
        max_seconds=0.4,
        threshold_seconds=0.2,
        exceeded_threshold=True,
    )
    fake_probe = type("FakeProbe", (), {"snapshot": lambda self: snapshot})()
    monkeypatch.setattr(checks, "get_loop_latency_probe", lambda: fake_probe)
    monkeypatch.setattr(checks, "get_event_loop_blocking_watchdog", lambda: None)

    runner = DoctorRunner()
    checks._check_event_loop_diagnostics(runner)

    finding = runner.report.find("runtime.event_loop_latency")
    assert finding is not None
    assert finding.status == DoctorFindingStatus.Degraded
