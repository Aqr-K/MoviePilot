"""S8 ⑦a 单元测试：__default_callback 就地分解。

把 god-method ``__default_callback`` 拆成薄编排 + 5 个单下划线私有 helper（失败/成功分支、
结果事件派发、完成通知、移动清理），行为字节等价。本套覆盖唯一含**新逻辑**的点——
``_dispatch_transfer_result_event``（把原成功/失败两处逐字重复的「媒体/字幕/音频」三路事件
派发合并为一个按 success 参数选 EventType 三元组的 helper），并守卫分解后的结构契约：
``__default_callback`` 仍是 name-mangled 私有方法（调用点 ``self.__default_callback`` 仍解析），
5 个 helper 存在。

app/chain/transfer.py 本身 agent/jieba-free，可直接 import。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from app.chain.transfer import TransferChain
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
    """_dispatch_transfer_result_event：success × 文件类型 → 正确 EventType + 兼容载荷。"""

    def setUp(self):
        self.chain = make_transfer_chain()
        self.chain.eventmanager = Mock()
        self.transferinfo = SimpleNamespace(name="ti")
        self.history = SimpleNamespace(id=99)

    def _dispatch(self, fileitem, *, success):
        self.chain._dispatch_transfer_result_event(
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
        self.chain._dispatch_transfer_result_event(
            _task(make_fileitem("/dl/a.mkv")), self.transferinfo, None, success=True
        )
        self.assertIsNone(
            self.chain.eventmanager.send_event.call_args.args[1]["transfer_history_id"]
        )


class DefaultCallbackDecomposeContractTest(unittest.TestCase):
    """分解后的结构契约：编排入口仍 mangled（调用点解析不变）+ 5 个 helper 存在。"""

    def test_orchestrator_still_name_mangled(self):
        # put_to_queue / do_transfer 以 self.__default_callback 取引用 → 须保留 mangled 名
        self.assertTrue(hasattr(TransferChain, "_TransferChain__default_callback"))

    def test_five_helpers_exist(self):
        for name in (
                "_dispatch_transfer_result_event",
                "_handle_transfer_failure",
                "_handle_transfer_success",
                "_notify_transfer_complete",
                "_cleanup_torrents_move_mode",
        ):
            self.assertTrue(callable(getattr(TransferChain, name, None)), name)


if __name__ == "__main__":
    unittest.main()
