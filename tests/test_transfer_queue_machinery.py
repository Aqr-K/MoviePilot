"""S8-step2 安全网（建设中）：transfer 队列/守护/worker 机器的特征化测试。

本批先验证 make_queue_chain() 夹具契约（不起线程即可种入机器属性），为后续
__start_transfer worker loop / 生命周期 / 入队的特征化测试奠基；这些特征化测试是
把队列/守护/计数器机器抽成 TransferService 前的行为锁。
"""
import queue
import unittest

from app.chain.transfer import JobManager
from tests.transfer_fixtures import make_queue_chain


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


if __name__ == "__main__":
    unittest.main()
