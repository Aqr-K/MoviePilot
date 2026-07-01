"""#7 回归：monitor 动态间隔调整须用 reschedule_job（APScheduler 3.x 修改触发器的正确入口）。

原代码用 modify_job(trigger='interval', minutes=N)：modify_job 将 trigger='interval' 字符串
直传 Job._modify（要求 BaseTrigger 实例），抛错后被 polling_observer 的宽 except 吞掉，
动态间隔调整永久失效。本用例锁定 reschedule_job 能按字符串触发器+minutes 正确改写间隔。
"""
import unittest

from apscheduler.schedulers.background import BackgroundScheduler


def _noop():
    pass


class TestMonitorRescheduleInterval(unittest.TestCase):
    def setUp(self):
        self.sched = BackgroundScheduler()
        self.sched.add_job(_noop, trigger="interval", minutes=10, id="monitor_test")

    def tearDown(self):
        try:
            self.sched.shutdown(wait=False)
        except Exception:
            pass

    def test_reschedule_job_changes_interval(self):
        """reschedule_job(trigger='interval', minutes=N) 正确改写间隔且不抛错。"""
        self.sched.reschedule_job("monitor_test", trigger="interval", minutes=5)
        job = self.sched.get_job("monitor_test")
        self.assertEqual(job.trigger.interval.total_seconds() / 60, 5)


if __name__ == "__main__":
    unittest.main()
