"""S8-step2 安全网：transfer 队列/守护/worker 机器的特征化测试。

S8-step2 ⑤ 已落地——队列机器从 TransferChain 抽到 TransferService（组合于 ``chain._service``）。
本套测试驱动/断言 ``chain._service`` 上的 worker loop (run_worker) / 生命周期 (start/stop) /
入队 (put_to_queue→service.enqueue)，作为抽取的行为锁；worker 仍经
``self._chain._TransferChain__handle_transfer`` / ``__fail_transfer_task`` 回调单例
（p115 契约 read-through），故注入点仍在 chain 上。
"""
import queue
import threading
import unittest
from unittest.mock import patch

from app.core.config import global_vars
from app.chain.transfer import JobManager
from app.schemas.transfer import TransferQueue
from tests.transfer_fixtures import make_queue_chain, make_task


def _drain_worker(chain, items, timeout=5):
    """预填 items，在线程里跑 service.run_worker 至全部 task_done，再停循环并 join。

    确定性要点：(1) 不向队列投 sentinel——worker 对 `if not item: continue` 不调用
    task_done()，投 None 会让 queue.join() 永久挂起，且会污染序列末尾的 _queue.empty() 检查；
    (2) queue.join() 等所有项 task_done（task_done 是 finally 首行）后再翻 _queue_active=False，
    worker 在下一次 0.01s 超时的 get 后从 while 顶退出，最后一项的 finally（含序列末尾
    progress.end + 计数重置）已在此前同步跑完。
    """
    global_vars.resume_system()  # 确保 STOP_EVENT 未设 → is_system_stopped False
    svc = chain._service
    svc._queue_active = True
    for it in items:
        svc._queue.put(it)
    t = threading.Thread(target=svc.run_worker, daemon=True)
    t.start()
    svc._queue.join()
    svc._queue_active = False
    t.join(timeout=timeout)
    return t


class MakeQueueChainContractTest(unittest.TestCase):
    def test_seeds_service_machinery_without_threads(self):
        """make_queue_chain 组合一个未起线程的 TransferService，机器态就绪，契约态仍在 chain。"""
        chain = make_queue_chain()
        svc = chain._service
        # 队列就绪且为空
        self.assertIsInstance(svc._queue, queue.Queue)
        self.assertTrue(svc._queue.empty())
        # 无线程被启动（构造态，start() 未调用 → worker loop 可被受控单步驱动）
        self.assertEqual([], svc._threads)
        self.assertEqual([], svc._transfer_threads)
        self.assertFalse(svc._queue_active)
        # 极小轮询间隔（夹具覆盖为 0.01）
        self.assertLess(svc._transfer_interval, 1)
        # 计数器清零
        self.assertEqual(0, svc._active_tasks)
        self.assertEqual(0, svc._processed_num)
        self.assertEqual(0, svc._fail_num)
        self.assertEqual(0, svc._total_num)
        # service read-through 回单例
        self.assertIs(chain, svc._chain)
        # 契约态仍在 TransferChain（jobview/_success_target_files/_scrape_batches）
        self.assertIsInstance(chain.jobview, JobManager)
        self.assertEqual({}, chain._success_target_files)
        self.assertEqual({}, chain._scrape_batches)

    def test_queue_put_get_roundtrip(self):
        """种入的 service._queue 是可用的 queue.Queue（put/get 往返）。"""
        chain = make_queue_chain()
        sentinel = object()
        chain._service._queue.put(sentinel)
        self.assertFalse(chain._service._queue.empty())
        self.assertIs(sentinel, chain._service._queue.get_nowait())
        self.assertTrue(chain._service._queue.empty())


class WorkerLoopCharacterizationTest(unittest.TestCase):
    """特征化 service.run_worker 的计数器/进度/异常行为（抽 TransferService 后的行为锁）。

    断言以 service._progress（Mock）的调用参数为准——这些在调用时即被捕获，不受序列末尾计数重置影响。
    worker 经 self._chain._TransferChain__handle_transfer / __fail_transfer_task 回调单例，
    故下面替换这两者于 chain 实例上即可注入。
    """

    def _run(self, results):
        """results: 每项一个 (state, errmsg) 元组或一个 Exception 实例。

        返回 (chain, handle_calls, fail_calls)。worker 串行处理，故 results 顺序即处理顺序。
        """
        chain = make_queue_chain()
        handle_calls = []
        counter = {"i": 0}

        def fake_handle(task, callback=None):
            i = counter["i"]
            counter["i"] += 1
            handle_calls.append((task, callback))
            r = results[i]
            if isinstance(r, Exception):
                raise r
            return r

        # 替换单例上的 __handle_transfer / __fail_transfer_task（worker 经 self._chain 回调）
        chain._TransferChain__handle_transfer = fake_handle
        fail_calls = []
        chain._TransferChain__fail_transfer_task = lambda task: fail_calls.append(task)

        items = [
            TransferQueue(task=make_task(i + 1), callback=None)
            for i in range(len(results))
        ]
        t = _drain_worker(chain, items)
        self.assertFalse(t.is_alive(), "worker 线程未在超时内退出")
        return chain, handle_calls, fail_calls

    def _end_msg(self, chain):
        """从 service._progress.update 调用里取序列末尾消息（唯一含『共整理』）。"""
        for c in chain._service._progress.update.call_args_list:
            text = c.kwargs.get("text", "")
            if "共整理" in text:
                return text
        return None

    def test_all_success_counts_and_progress_lifecycle(self):
        """3 项全成功：每项调用一次 handle、序列起始/结束各一次、末尾消息失败 0、计数归零。"""
        chain, handle_calls, _ = self._run([(True, ""), (True, ""), (True, "")])
        self.assertEqual(3, len(handle_calls))
        chain._service._progress.start.assert_called_once()
        chain._service._progress.end.assert_called_once()
        self.assertIn("共整理 3 个文件，失败 0 个", self._end_msg(chain))
        self.assertEqual(0, chain._service._active_tasks)
        self.assertEqual(0, chain._service._processed_num)
        self.assertEqual(0, chain._service._fail_num)

    def test_failures_counted_in_end_message(self):
        """3 项 2 失败（handle 返回 (False, ...)）：末尾消息失败计数为 2。"""
        chain, _, _ = self._run([(True, ""), (False, "x"), (False, "y")])
        self.assertIn("共整理 3 个文件，失败 2 个", self._end_msg(chain))
        chain._service._progress.end.assert_called_once()

    def test_exception_path_invokes_fail_transfer_task_and_counts(self):
        """handle 抛异常：走 __fail_transfer_task，且该项计入 processed 与 fail。"""
        chain, handle_calls, fail_calls = self._run(
            [(True, ""), RuntimeError("boom"), (True, "")]
        )
        self.assertEqual(3, len(handle_calls))
        self.assertEqual(1, len(fail_calls))
        self.assertIn("共整理 3 个文件，失败 1 个", self._end_msg(chain))

    def test_empty_task_item_is_skipped(self):
        """TransferQueue.task 为空：worker task_done 后跳过，不调用 handle。"""
        chain = make_queue_chain()
        handle_calls = []
        chain._TransferChain__handle_transfer = (
            lambda task, callback=None: handle_calls.append(task) or (True, "")
        )
        items = [
            TransferQueue(task=None, callback=None),
            TransferQueue(task=make_task(1), callback=None),
        ]
        t = _drain_worker(chain, items)
        self.assertFalse(t.is_alive())
        self.assertEqual(1, len(handle_calls))


class LifecycleCharacterizationTest(unittest.TestCase):
    """特征化守护线程生命周期 service.start/stop 与 chain.on_config_changed（在 make_queue_chain
    的 service 上手动驱动，不构造真实 TransferChain()——避 Singleton 跨测试泄漏；空队列下线程仅
    0.01s 自旋，stop 快速 join）。
    """

    def setUp(self):
        global_vars.resume_system()  # 确保线程进入 loop（is_system_stopped False）

    def test_start_spawns_daemon_threads_then_stop_joins(self):
        """start 起 TRANSFER_THREADS 个具名守护线程并置 _queue_active；stop 翻标志、join、清空。"""
        chain = make_queue_chain()
        svc = chain._service
        with patch("app.chain.transfer.settings.TRANSFER_THREADS", 2):
            svc.start()
        try:
            self.assertTrue(svc._queue_active)
            self.assertEqual(2, len(svc._threads))
            for i, th in enumerate(svc._threads):
                self.assertTrue(th.is_alive())
                self.assertTrue(th.daemon)
                self.assertEqual(f"transfer-{i}", th.name)
        finally:
            svc.stop()
        self.assertFalse(svc._queue_active)
        self.assertEqual([], svc._threads)

    def test_on_config_changed_restarts_threads(self):
        """chain.on_config_changed 委派 service.stop+start：旧线程被 join 退出，换上等量新线程。"""
        chain = make_queue_chain()
        svc = chain._service
        with patch("app.chain.transfer.settings.TRANSFER_THREADS", 1):
            svc.start()
            first = list(svc._threads)
            chain.on_config_changed()
            second = list(svc._threads)
            try:
                self.assertEqual(1, len(second))
                self.assertIsNot(first[0], second[0])
                self.assertFalse(first[0].is_alive())
                self.assertTrue(second[0].is_alive())
            finally:
                svc.stop()
        self.assertEqual([], svc._threads)


class EnqueueCharacterizationTest(unittest.TestCase):
    """特征化入队 chain.put_to_queue（去重/刮削登记仍在 chain，落队委派 service.enqueue）。"""

    def test_put_to_queue_none_returns_false(self):
        """空任务：返回 False，不入队。"""
        chain = make_queue_chain()
        self.assertFalse(chain.put_to_queue(None))
        self.assertTrue(chain._service._queue.empty())

    def test_put_to_queue_lands_task_with_default_callback(self):
        """有效任务：入队一个 TransferQueue(task, callback=__default_callback)，并登记进 jobview。"""
        chain = make_queue_chain()
        task = make_task(1)
        self.assertTrue(chain.put_to_queue(task))
        self.assertEqual(1, chain._service._queue.qsize())
        item = chain._service._queue.get_nowait()
        self.assertIs(task, item.task)
        self.assertEqual(chain._TransferChain__default_callback, item.callback)
        self.assertEqual(1, len(chain.jobview.list_jobs()))

    def test_put_to_queue_dedupes_same_task(self):
        """同一 fileitem 再次入队：jobview.add_task 报重复 → 返回 False，不重复入队。"""
        chain = make_queue_chain()
        task = make_task(1)
        self.assertTrue(chain.put_to_queue(task))
        self.assertFalse(chain.put_to_queue(task))
        self.assertEqual(1, chain._service._queue.qsize())


if __name__ == "__main__":
    unittest.main()
