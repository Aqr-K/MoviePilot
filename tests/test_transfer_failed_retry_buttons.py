import unittest
import sys
from types import ModuleType
from unittest.mock import patch

sys.modules.setdefault("qbittorrentapi", ModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", ModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)
sys.modules.setdefault("psutil", ModuleType("psutil"))

from app.chain.message import MessageChain
from app.chain.transfer import TransferChain
from app.core.config import settings
from app.schemas.types import MessageChannel


class TestTransferFailedRetryButtons(unittest.TestCase):
    def test_build_failed_transfer_buttons(self):
        buttons = TransferChain.build_failed_transfer_buttons(12)

        self.assertEqual(
            buttons,
            [
                [
                    {"text": "重试", "callback_data": "transfer_retry_12"},
                    {
                        "text": "智能助手接管",
                        "callback_data": "transfer_ai_retry_12",
                    },
                ]
            ],
        )

    def test_remote_transfer_supports_history_only_retry(self):
        chain = TransferChain()

        with patch.object(chain, "redo_transfer_history", return_value=(True, "")) as redo:
            with patch.object(chain, "post_message") as post_message:
                chain.remote_transfer(
                    "12",
                    channel=MessageChannel.Telegram,
                    userid="10001",
                    source="telegram-test",
                )

        redo.assert_called_once_with(12)
        post_message.assert_not_called()

    def test_transfer_retry_callback_retries_history(self):
        chain = MessageChain()

        with patch("app.chain.message.TransferChain") as transfer_cls:
            transfer_cls.return_value.redo_transfer_history.return_value = (True, "")
            with patch.object(chain, "post_message") as post_message:
                chain._handle_callback(
                    text="CALLBACK:transfer_retry_12",
                    channel=MessageChannel.Telegram,
                    source="telegram-test",
                    userid="10001",
                    username="tester",
                )

        transfer_cls.return_value.redo_transfer_history.assert_called_once_with(12)
        self.assertEqual(post_message.call_count, 2)
        self.assertEqual(
            post_message.call_args_list[0].args[0].title,
            "开始重新整理记录 #12 ...",
        )
        self.assertEqual(
            post_message.call_args_list[1].args[0].title,
            "整理记录 #12 已重新整理",
        )

    def test_transfer_ai_retry_callback_schedules_agent_takeover(self):
        chain = MessageChain()

        with patch.object(settings, "AI_AGENT_ENABLE", True):
            with patch("app.chain.message.asyncio.run_coroutine_threadsafe") as run_task:
                with patch.object(chain, "post_message") as post_message:
                    chain._handle_callback(
                        text="CALLBACK:transfer_ai_retry_34",
                        channel=MessageChannel.Telegram,
                        source="telegram-test",
                        userid="10001",
                        username="tester",
                    )

        run_task.assert_called_once()
        self.assertEqual(post_message.call_count, 1)
        self.assertEqual(
            post_message.call_args_list[0].args[0].title,
            "已将整理记录 #34 交给智能助手处理",
        )


if __name__ == "__main__":
    unittest.main()
