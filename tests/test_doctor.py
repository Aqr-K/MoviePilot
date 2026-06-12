from __future__ import annotations

from app.core.config import settings
from app.doctor import run_doctor
from app.doctor.formatters import format_json_report, format_text_report
from app.doctor.models import DoctorFinding, DoctorFindingStatus, DoctorSeverity


def test_doctor_report_has_stable_json_shape(tmp_path, monkeypatch):
    """doctor JSON 报告应包含稳定状态、环境、汇总和发现列表。"""
    monkeypatch.setattr(settings, "CONFIG_DIR", str(tmp_path))
    (settings.LOG_PATH).mkdir(parents=True, exist_ok=True)
    (settings.ROOT_PATH / "public").mkdir(exist_ok=True)

    report = run_doctor()
    payload = report.to_dict()

    assert payload["schema_version"] == 1
    assert payload["status"] in {"healthy", "degraded", "failed"}
    assert payload["environment"]["config_path"] == str(tmp_path)
    assert isinstance(payload["summary"]["total"], int)
    assert isinstance(payload["findings"], list)
    assert any(item["id"] == "runtime.paths" for item in payload["findings"])


def test_doctor_formatters_include_status_and_finding(tmp_path, monkeypatch):
    """doctor 文本和 JSON 格式化应展示状态与诊断项。"""
    monkeypatch.setattr(settings, "CONFIG_DIR", str(tmp_path))
    report = run_doctor()
    report.add_finding(
        DoctorFinding(
            id="test.demo",
            severity=DoctorSeverity.Warn,
            status=DoctorFindingStatus.Degraded,
            title="测试诊断项",
            detail="测试原因",
            recommendation="测试建议",
        )
    )

    text = format_text_report(report)
    json_text = format_json_report(report)

    assert "MoviePilot Doctor" in text
    assert "测试诊断项" in text
    assert '"schema_version": 1' in json_text
    assert '"test.demo"' in json_text


def test_doctor_fix_removes_stale_runtime(tmp_path, monkeypatch):
    """doctor --fix 应清理指向失效进程的 runtime 文件。"""
    monkeypatch.setattr(settings, "CONFIG_DIR", str(tmp_path))
    settings.TEMP_PATH.mkdir(parents=True, exist_ok=True)
    runtime_file = settings.TEMP_PATH / "moviepilot.runtime.json"
    runtime_file.write_text('{"pid": 999999, "create_time": 1}', encoding="utf-8")

    report = run_doctor(fix=True)

    assert not runtime_file.exists()
    finding = report.find("runtime.backend_stale")
    assert finding is not None
    assert finding.fixed
