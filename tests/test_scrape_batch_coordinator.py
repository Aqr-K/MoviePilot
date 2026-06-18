"""S8 ⑥ 单元测试：ScrapeBatchCoordinator（批次级刮削事件协调器，从 TransferChain 抽出）。

协调器把同一整理批次（``transfer_batch_id``）内多文件的刮削目标聚合，待批次关闭（``close``）
且批内任务全部结束（``finish`` 把 pending 清空）后，统一发一次 ``MetadataScrape`` 事件——
避免逐文件重复触发目录刮削。

这些测试不构造真实 TransferChain（避 Singleton 跨测试泄漏 + jieba_next 环境块），而以
SimpleNamespace 伪造 ``_chain``：协调器只 read-through 读取它的 ``eventmanager``（捕获事件）
与 name-mangled ``_TransferChain__is_media_file``（判定是否媒体文件）。``_batches`` 是协调器
自己的状态（原 ``TransferChain._scrape_batches``，非 p115 触达点）。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from app.chain.transfer import ScrapeBatchCoordinator
from app.schemas.types import EventType


def _fake_chain(is_media: bool = True) -> SimpleNamespace:
    """伪造 chain：仅暴露协调器 read-through 的两个面 —— eventmanager 与 __is_media_file。"""
    return SimpleNamespace(
        eventmanager=Mock(),
        # 单前导下划线 → 不被 mangling，恰好命中协调器内 self._chain._TransferChain__is_media_file
        _TransferChain__is_media_file=lambda fileitem: is_media,
    )


def _task(batch_id="b1", path="/dl/a.mkv") -> SimpleNamespace:
    return SimpleNamespace(
        transfer_batch_id=batch_id,
        fileitem=SimpleNamespace(path=path),
        meta=SimpleNamespace(title="Show"),
        mediainfo=SimpleNamespace(title_year="Show (2026)"),
    )


def _transferinfo(target_path="/lib/Show", files=None, need_scrape=True) -> SimpleNamespace:
    return SimpleNamespace(
        need_scrape=need_scrape,
        target_diritem=SimpleNamespace(storage="local", path=target_path),
        file_list_new=files if files is not None else ["/lib/Show/a.mkv"],
    )


class ScrapeBatchCoordinatorTest(unittest.TestCase):
    def test_aggregates_and_emits_once_after_batch_complete(self):
        """register → record → close（pending 未空，不发） → finish（pending 空 → 唯一一次发送）。"""
        chain = _fake_chain()
        coord = ScrapeBatchCoordinator(chain=chain)
        task = _task()

        coord.register(task)
        coord.record_target(task, _transferinfo(files=["/lib/Show/a.mkv"]))
        coord.close(task.transfer_batch_id)
        chain.eventmanager.send_event.assert_not_called()  # 批已关闭但任务未结束 → 不发

        coord.finish(task)
        chain.eventmanager.send_event.assert_called_once()
        evt_type, payload = chain.eventmanager.send_event.call_args.args
        self.assertEqual(EventType.MetadataScrape, evt_type)
        self.assertEqual(["/lib/Show/a.mkv"], payload["file_list"])
        self.assertIs(task.meta, payload["meta"])
        self.assertIs(task.mediainfo, payload["mediainfo"])
        self.assertEqual("/lib/Show", payload["fileitem"].path)
        self.assertEqual({}, coord._batches)  # 发后批次被清出

    def test_two_files_same_batch_aggregate_into_single_event(self):
        """同批两任务、同目标根目录：聚合进一次事件，file_list 去重含两文件。"""
        chain = _fake_chain()
        coord = ScrapeBatchCoordinator(chain=chain)
        t1 = _task(path="/dl/a.mkv")
        t2 = _task(path="/dl/b.mkv")

        coord.register(t1)
        coord.register(t2)
        coord.record_target(t1, _transferinfo(files=["/lib/Show/a.mkv"]))
        coord.record_target(t2, _transferinfo(files=["/lib/Show/b.mkv", "/lib/Show/a.mkv"]))
        coord.close("b1")
        coord.finish(t1)
        chain.eventmanager.send_event.assert_not_called()  # t2 仍 pending
        coord.finish(t2)

        chain.eventmanager.send_event.assert_called_once()
        _, payload = chain.eventmanager.send_event.call_args.args
        self.assertEqual(["/lib/Show/a.mkv", "/lib/Show/b.mkv"], payload["file_list"])  # 去重保序
        self.assertEqual({}, coord._batches)

    def test_no_batch_id_is_noop(self):
        """无 transfer_batch_id：register/record/close/finish 全为空操作，不发事件、不留状态。"""
        chain = _fake_chain()
        coord = ScrapeBatchCoordinator(chain=chain)
        task = _task(batch_id=None)

        coord.register(task)
        coord.record_target(task, _transferinfo())
        coord.close(None)
        coord.finish(task)

        chain.eventmanager.send_event.assert_not_called()
        self.assertEqual({}, coord._batches)

    def test_non_media_file_records_no_target_so_no_event(self):
        """非媒体文件：record_target 不登记目标 → 批次关闭并结束后无目标可发，但状态仍被清出。"""
        chain = _fake_chain(is_media=False)
        coord = ScrapeBatchCoordinator(chain=chain)
        task = _task()

        coord.register(task)
        coord.record_target(task, _transferinfo())  # 非媒体 → 不登记
        coord.close("b1")
        coord.finish(task)

        chain.eventmanager.send_event.assert_not_called()
        self.assertEqual({}, coord._batches)


if __name__ == "__main__":
    unittest.main()
