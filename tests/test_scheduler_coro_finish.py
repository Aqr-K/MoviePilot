"""P0 PR-B 单测：scheduler 协程定时任务的 Future 收口。

修复前 __start_coro 提交协程后立即返回、__finish_job 随即复位 running 标志：
① 协程异常在事件循环里丢失（异常黑洞）；② running 提前复位导致重入并发。
修复后 start() 阻塞至协程真正完成，异常经 .result() 重新抛出被 except 捕获。
"""
import asyncio
import threading

import pytest
from unittest.mock import patch

from app.core.config import global_vars
from app.scheduler import Scheduler


def _bare_scheduler() -> Scheduler:
    """构造不触发重初始化的裸 Scheduler 实例（绕过 SingletonClass.__call__）。"""
    s = Scheduler.__new__(Scheduler)
    s._jobs = {}
    s._lock = threading.RLock()
    return s


@pytest.fixture
def bg_loop():
    """在后台线程起一个事件循环并注入 global_vars，模拟主循环。"""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    prev = global_vars.CURRENT_EVENT_LOOP
    global_vars.set_loop(loop)
    try:
        yield loop
    finally:
        global_vars.set_loop(prev)
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
        loop.close()


class TestSchedulerCoroutineFinish:

    def test_start_blocks_until_coroutine_completes(self, bg_loop):
        s = _bare_scheduler()
        done = threading.Event()

        async def slow_job():
            await asyncio.sleep(0.15)
            done.set()

        s._jobs["job_ok"] = {"func": slow_job, "name": "job_ok"}
        s.start("job_ok")
        # 修复后 start 应阻塞到协程真正结束（异常黑洞/重入根因）
        assert done.is_set()
        assert s._jobs["job_ok"]["running"] is False

    def test_coroutine_exception_is_reported(self, bg_loop):
        s = _bare_scheduler()

        async def failing_job():
            await asyncio.sleep(0.02)
            raise RuntimeError("boom")

        s._jobs["job_err"] = {"func": failing_job, "name": "job_err"}
        with patch("app.scheduler.logger") as mock_logger, \
             patch("app.scheduler.eventmanager") as mock_evt, \
             patch("app.scheduler.MessageHelper"):
            s.start("job_err")
        # 修复后协程异常经 .result() 重新抛出 → 被 except 捕获 → 记录并发事件
        assert mock_logger.error.called
        assert mock_evt.send_event.called
        assert s._jobs["job_err"]["running"] is False
