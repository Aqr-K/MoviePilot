"""S8-step2 安全网（建设中）：transfer 队列/守护/worker 机器的特征化测试。

本批先验证 make_queue_chain() 夹具契约（不起线程即可种入机器属性），为后续
__start_transfer worker loop / 生命周期 / 入队的特征化测试奠基；这些特征化测试是
把队列/守护/计数器机器抽成 TransferService 前的行为锁。
"""
import queue
import threading
import unittest

from app.core.config import global_vars
from app.chain.transfer import JobManager
from app.schemas.transfer import TransferQueue
from tests.transfer_fixtures import make_queue_chain, make_task


def _drain_worker(chain, items, timeout=5):
    """预填 items，在线程里跑 __start_transfer 至全部 task_done，再停循环并 join。

    确定性要点：(1) 不向队列投 sentinel——worker 对 `if not item: continue` 不调用
    task_done()，投 None 会让 queue.join() 永久挂起，且会污染序列末尾的 _queue.empty() 检查；
    (2) queue.join() 等所有项 task_done（task_done 是 finally 首行）后再翻 _queue_active=False，
    worker 在下一次 0.01s 超时的 get 后从 while 顶退出，最后一项的 finally（含序列末尾
    progress.end + 计数重置）已在此前同步跑完。
    """
    global_vars.resume_system()  # 确保 STOP_EVENT 未设 → is_system_stopped False
    chain._queue_active = True
    for it in items:
        chain._queue.put(it)
    t = threading.Thread(target=chain._TransferChain__start_transfer, daemon=True)
    t.start()
    chain._queue.join()
    chain._queue_active = False
    t.join(timeout=timeout)
    return t


class MakeQueueChainContractTest(unittest.TestCase):
    def test_seeds_machinery_attrs_without_threads(self):
        """make_queue_chain 种入队列/计数器/守护属性，且不 spawn 任何线程。"""
        chain = make_queue_chain()
        # 队列就绪且为空
        self.assertIsInstance(chain._queue, queue.Queue)
        self.assertTrue(chain._queue.empty())
        # 无线程被启动（worker loop 可被受控单步驱动，不阻塞在 15s 的 _queue.get）
        self.assertEqual([], chain._threads)
        self.assertEqual([], chain._transfer_threads)
        # 守护 run 标志 + 极小轮询间隔
        self.assertTrue(chain._queue_active)
        self.assertLess(chain._transfer_interval, 1)
        # 计数器清零
        self.assertEqual(0, chain._active_tasks)
        self.assertEqual(0, chain._processed_num)
        self.assertEqual(0, chain._fail_num)
        self.assertEqual(0, chain._total_num)
        # 复用 make_transfer_chain 的 jobview/_success_target_files/_scrape_batches
        self.assertIsInstance(chain.jobview, JobManager)
        self.assertEqual({}, chain._success_target_files)
        self.assertEqual({}, chain._scrape_batches)

    def test_queue_put_get_roundtrip(self):
        """种入的 _queue 是可用的 queue.Queue（put/get 往返）。"""
        chain = make_queue_chain()
        sentinel = object()
        chain._queue.put(sentinel)
        self.assertFalse(chain._queue.empty())
        self.assertIs(sentinel, chain._queue.get_nowait())
        self.assertTrue(chain._queue.empty())


class WorkerLoopCharacterizationTest(unittest.TestCase):
    """特征化 __start_transfer worker loop 的计数器/进度/异常行为（抽 TransferService 前的行为锁）。

    断言以 _progress（Mock）的调用参数为准——这些在调用时即被捕获，不受序列末尾计数重置影响。
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

        # 实例属性遮蔽类方法：self.__handle_transfer 解析到 _TransferChain__handle_transfer 实例属性
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
        """从 _progress.update 调用里取序列末尾消息（唯一含『共整理』）。"""
        for c in chain._progress.update.call_args_list:
            text = c.kwargs.get("text", "")
            if "共整理" in text:
                return text
        return None

    def test_all_success_counts_and_progress_lifecycle(self):
        """3 项全成功：每项调用一次 handle、序列起始/结束各一次、末尾消息失败 0、计数归零。"""
        chain, handle_calls, _ = self._run([(True, ""), (True, ""), (True, "")])
        self.assertEqual(3, len(handle_calls))
        chain._progress.start.assert_called_once()
        chain._progress.end.assert_called_once()
        self.assertIn("共整理 3 个文件，失败 0 个", self._end_msg(chain))
        self.assertEqual(0, chain._active_tasks)
        self.assertEqual(0, chain._processed_num)
        self.assertEqual(0, chain._fail_num)

    def test_failures_counted_in_end_message(self):
        """3 项 2 失败（handle 返回 (False, ...)）：末尾消息失败计数为 2。"""
        chain, _, _ = self._run([(True, ""), (False, "x"), (False, "y")])
        self.assertIn("共整理 3 个文件，失败 2 个", self._end_msg(chain))
        chain._progress.end.assert_called_once()

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


if __name__ == "__main__":
    unittest.main()
