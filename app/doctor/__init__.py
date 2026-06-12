from app.doctor.models import DoctorFinding, DoctorReport
from app.doctor.runner import DoctorRunner


def run_doctor(*, fix: bool = False, deep: bool = False) -> DoctorReport:
    """
    运行 MoviePilot 离线诊断并返回报告。
    """
    return DoctorRunner(fix=fix, deep=deep).run()


__all__ = [
    "DoctorFinding",
    "DoctorReport",
    "DoctorRunner",
    "run_doctor",
]
