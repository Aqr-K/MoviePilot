"""S8 ⑦a/⑦b 单元测试：整理完成回调的分解与迁出。

⑦a 把 god-method ``__default_callback`` 就地拆成薄编排 + 5 个私有 helper；⑦b 把这一簇整体
迁入独立类 ``TransferResultProcessor``（组合于单例 ``chain._result_processor``），原 chain 方法
``__default_callback`` 消失、回调改由处理器的 ``handle`` 提供。本套覆盖唯一含**新逻辑**的点——
``_dispatch_transfer_result_event``（把原成功/失败两处逐字重复的「媒体/字幕/音频」三路事件
派发合并为一个按 success 参数选 EventType 三元组的 helper），并守卫迁出后的结构契约：处理器
暴露 ``handle`` + 5 helper + 迁入的 2 个私有方法，且 ``__default_callback`` 已从 TransferChain 移除。

处理器经 ``self._chain`` read-through 读取 ``eventmanager`` 与 mangled ``__is_*_file``，故测试以
``make_transfer_chain()`` 夹具（已种 ``_result_processor`` + 扩展名分类用的 ``_media_exts`` 等）驱动，
``chain.eventmanager`` 用 Mock 捕获事件。app/chain/transfer.py 本身 agent/jieba-free，可直接 import。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from app.chain.transfer import TransferChain, TransferResultProcessor
from app.schemas.types import EventType
from tests.transfer_fixtures import make_fileitem, make_transfer_chain


def _task(fileitem) -> SimpleNamespace:
    return SimpleNamespace(
        fileitem=fileitem,
        meta=SimpleNamespace(title="Show"),
        mediainfo=SimpleNamespace(title_year="Show (2026)"),
        downloader="qb",
        download_hash="hash123",
    )


class DispatchTransferResultEventTest(unittest.TestCase):
    """processor._dispatch_transfer_result_event：success × 文件类型 → 正确 EventType + 兼容载荷。"""

    def setUp(self):
        self.chain = make_transfer_chain()
        self.chain.eventmanager = Mock()  # 处理器 read-through self._chain.eventmanager
        self.processor = self.chain._result_processor
        self.transferinfo = SimpleNamespace(name="ti")
        self.history = SimpleNamespace(id=99)

    def _dispatch(self, fileitem, *, success):
        self.processor._dispatch_transfer_result_event(
            _task(fileitem), self.transferinfo, self.history, success=success
        )
        return self.chain.eventmanager.send_event

    def test_success_media_emits_transfer_complete_with_payload(self):
        send = self._dispatch(make_fileitem("/dl/a.mkv"), success=True)
        send.assert_called_once()
        evt, payload = send.call_args.args
        self.assertEqual(EventType.TransferComplete, evt)
        self.assertEqual("/dl/a.mkv", payload["fileitem"].path)
        self.assertIs(self.transferinfo, payload["transferinfo"])
        self.assertEqual("qb", payload["downloader"])
        self.assertEqual("hash123", payload["download_hash"])
        self.assertEqual(99, payload["transfer_history_id"])

    def test_failure_media_emits_transfer_failed(self):
        send = self._dispatch(make_fileitem("/dl/a.mkv"), success=False)
        self.assertEqual(EventType.TransferFailed, send.call_args.args[0])

    def test_subtitle_maps_to_subtitle_events(self):
        self.assertEqual(
            EventType.SubtitleTransferComplete,
            self._dispatch(make_fileitem("/dl/a.srt"), success=True).call_args.args[0],
        )
        self.chain.eventmanager.send_event.reset_mock()
        self.assertEqual(
            EventType.SubtitleTransferFailed,
            self._dispatch(make_fileitem("/dl/a.srt"), success=False).call_args.args[0],
        )

    def test_audio_maps_to_audio_events(self):
        self.assertEqual(
            EventType.AudioTransferComplete,
            self._dispatch(make_fileitem("/dl/a.aac"), success=True).call_args.args[0],
        )
        self.chain.eventmanager.send_event.reset_mock()
        self.assertEqual(
            EventType.AudioTransferFailed,
            self._dispatch(make_fileitem("/dl/a.aac"), success=False).call_args.args[0],
        )

    def test_unclassified_file_emits_no_event(self):
        """非媒体/字幕/音频（.txt）：原三路 if/elif/elif 无 else → 不发事件，行为保持。"""
        self._dispatch(make_fileitem("/dl/note.txt"), success=True)
        self._dispatch(make_fileitem("/dl/note.txt"), success=False)
        self.chain.eventmanager.send_event.assert_not_called()

    def test_history_none_yields_null_history_id(self):
        self.processor._dispatch_transfer_result_event(
            _task(make_fileitem("/dl/a.mkv")), self.transferinfo, None, success=True
        )
        self.assertIsNone(
            self.chain.eventmanager.send_event.call_args.args[1]["transfer_history_id"]
        )


class ResultProcessorExtractionContractTest(unittest.TestCase):
    """迁出后的结构契约：处理器暴露 handle + helper 簇；__default_callback 已离开 TransferChain。"""

    def test_default_callback_removed_from_chain(self):
        # 整理完成回调已迁入 TransferResultProcessor，chain 不再持有 mangled 方法
        self.assertFalse(hasattr(TransferChain, "_TransferChain__default_callback"))

    def test_processor_exposes_handle_and_helpers(self):
        for name in (
                "handle",
                "_dispatch_transfer_result_event",
                "_handle_transfer_failure",
                "_handle_transfer_success",
                "_notify_transfer_complete",
                "_cleanup_torrents_move_mode",
                # 仅 callback 簇使用、随簇迁入的两个私有方法（name-mangled 到处理器）
                "_TransferResultProcessor__get_transfer_target_dir_path",
                "_TransferResultProcessor__send_metadata_scrape_event",
        ):
            self.assertTrue(callable(getattr(TransferResultProcessor, name, None)), name)

    def test_chain_composes_processor_and_callback_is_handle(self):
        chain = make_transfer_chain()
        self.assertIsInstance(chain._result_processor, TransferResultProcessor)
        self.assertIs(chain, chain._result_processor._chain)
        # 入队回调即处理器 handle（bound 方法相等）
        self.assertEqual(chain._result_processor.handle, chain._result_processor.handle)


if __name__ == "__main__":
    unittest.main()
