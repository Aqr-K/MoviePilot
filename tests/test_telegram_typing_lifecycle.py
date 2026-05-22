import asyncio
import sys
import time
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.modules.setdefault("app.helper.sites", ModuleType("app.helper.sites"))
setattr(sys.modules["app.helper.sites"], "SitesHelper", object)

from app.agent import AgentManager, _MessageTask
from app.chain.message import MessageChain
from app.command import Command, _finish_command_processing_status
from app.modules.telegram import TelegramModule
from app.modules.telegram.telegram import Telegram
from app.schemas.types import MessageChannel


class TestTelegramTypingLifecycle(unittest.TestCase):
    def setUp(self):
        self._cleanup_typing_tasks()

    def tearDown(self):
        self._cleanup_typing_tasks()

    @staticmethod
    def _cleanup_typing_tasks():
        helper = Telegram.__new__(Telegram)
        for chat_id in list(Telegram._typing_tasks.keys()):
            helper._stop_typing_task(chat_id)
        Telegram._typing_tasks.clear()
        Telegram._typing_stop_flags.clear()
        Telegram._user_chat_mapping.clear()

    @staticmethod
    def _telegram_client() -> Telegram:
        telegram = Telegram.__new__(Telegram)
        telegram._bot = Mock()
        telegram._telegram_token = "token"
        telegram._telegram_chat_id = "default-chat"
        # 缩短测试中的等待时间，不改变生产默认续发间隔。
        telegram._typing_interval_seconds = 0.01
        telegram._typing_max_duration_seconds = 1
        return telegram

    def test_start_typing_can_stop_by_chat_id(self):
        telegram = self._telegram_client()

        telegram._start_typing_task("chat-1", max_duration_seconds=1)
        time.sleep(0.03)

        self.assertIn("chat-1", Telegram._typing_tasks)
        self.assertTrue(telegram._bot.send_chat_action.called)
        self.assertTrue(telegram.stop_typing(chat_id="chat-1"))
        self.assertNotIn("chat-1", Telegram._typing_tasks)

    def test_start_typing_can_stop_by_user_mapping(self):
        telegram = self._telegram_client()
        Telegram._user_chat_mapping["10001"] = "chat-2"

        telegram._start_typing_task("chat-2", max_duration_seconds=1)
        time.sleep(0.03)

        self.assertTrue(telegram.stop_typing(userid="10001"))
        self.assertNotIn("chat-2", Telegram._typing_tasks)

    def test_typing_task_has_max_duration_guard(self):
        telegram = self._telegram_client()

        telegram._start_typing_task("chat-3", max_duration_seconds=0.02)
        time.sleep(0.08)

        self.assertNotIn("chat-3", Telegram._typing_tasks)

    def test_agent_managed_send_msg_keeps_typing_for_worker_cleanup(self):
        telegram = self._telegram_client()
        sent = SimpleNamespace(message_id=1, chat=SimpleNamespace(id="chat-1"))

        with patch.object(
                telegram, "_Telegram__send_request", return_value=sent
        ), patch.object(telegram, "_stop_typing_task") as stop_typing:
            result = telegram.send_msg(
                title="处理中",
                userid="10001",
                stop_typing=False,
            )

        self.assertTrue(result["success"])
        stop_typing.assert_not_called()

    def test_send_msg_does_not_stop_typing_by_default(self):
        """
        响应发送不再默认结束 typing，由处理状态统一收口。
        """
        telegram = self._telegram_client()
        sent = SimpleNamespace(message_id=1, chat=SimpleNamespace(id="chat-1"))

        with patch.object(
                telegram, "_Telegram__send_request", return_value=sent
        ), patch.object(telegram, "_stop_typing_task") as stop_typing:
            result = telegram.send_msg(title="处理中", userid="10001")

        self.assertTrue(result["success"])
        stop_typing.assert_not_called()

    def test_telegram_module_processing_status_starts_typing(self):
        """
        Telegram 通过模块处理状态接口启动 typing 保活。
        """
        module = TelegramModule()
        module._channel = MessageChannel.Telegram
        client = Mock()
        client.start_typing.return_value = True

        with patch.object(
                module, "get_config", return_value=SimpleNamespace(name="telegram-test")
        ), patch.object(module, "get_instance", return_value=client):
            status = module.mark_message_processing_started(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                chat_id="-100",
                text="hello",
            )

        client.start_typing.assert_called_once_with(chat_id="-100", userid="10001")
        self.assertEqual(status["metadata"]["kind"], "typing")

    def test_slash_command_defers_processing_status_to_command_handler(self):
        chain = MessageChain.__new__(MessageChain)
        chain.eventmanager = Mock()
        status = MessageChain._ProcessingStatus(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            chat_id="-100",
            metadata={"kind": "typing"},
        )

        with patch.object(chain, "_record_user_message"), patch.object(
                chain, "_mark_message_processing_started", return_value=status
        ), patch.object(
                chain, "_mark_message_processing_finished"
        ) as finish_status:
            chain.handle_message(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                text="/sites",
                original_chat_id="-100",
            )

        finish_status.assert_not_called()
        chain.eventmanager.send_event.assert_called_once()
        self.assertEqual(
            chain.eventmanager.send_event.call_args.args[1]["processing_status"],
            status.to_dict(),
        )

    def test_command_handler_finishes_processing_status_after_execute(self):
        """
        传统命令响应完成后由命令处理器统一结束 processing status。
        """
        command = Command.__new__(Command)
        command.get = Mock(return_value={"func": Mock()})
        command.execute = Mock()
        event = SimpleNamespace(
            event_data={
                "cmd": "/sites",
                "user": "10001",
                "channel": MessageChannel.Telegram,
                "source": "telegram-test",
                "processing_status": {
                    "channel": MessageChannel.Telegram.value,
                    "source": "telegram-test",
                    "userid": "10001",
                    "chat_id": "-100",
                    "metadata": {"kind": "typing"},
                },
            }
        )

        with patch("app.command._finish_command_processing_status") as finish_status:
            command.command_event(event)

        command.execute.assert_called_once()
        finish_status.assert_called_once_with(
            event.event_data["processing_status"],
            user_id="10001",
        )

    def test_finish_command_processing_status_uses_module_interface(self):
        status = {
            "channel": MessageChannel.Telegram.value,
            "source": "telegram-test",
            "userid": "10001",
            "chat_id": "-100",
            "metadata": {"kind": "typing"},
        }

        with patch("app.command.CommandChain") as chain_cls:
            _finish_command_processing_status(status, user_id="fallback")

        chain_cls.return_value.run_module.assert_called_once_with(
            "mark_message_processing_finished",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            message_id=None,
            chat_id="-100",
            status=status,
        )

    def test_async_agent_keeps_processing_status_for_worker(self):
        chain = MessageChain.__new__(MessageChain)
        status = MessageChain._ProcessingStatus(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            chat_id="-100",
            metadata={"kind": "typing"},
        )

        with patch.object(chain, "_record_user_message"), patch.object(
                chain, "_mark_message_processing_started", return_value=status
        ), patch.object(chain, "_handle_message_core", return_value=True), patch.object(
                chain, "_mark_message_processing_finished"
        ) as finish_status:
            chain.handle_message(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                text="/ai 搜索电影",
                original_chat_id="-100",
            )

        finish_status.assert_not_called()

    def test_callback_stops_typing_when_message_handler_returns(self):
        chain = MessageChain.__new__(MessageChain)
        status = MessageChain._ProcessingStatus(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            chat_id="-100",
            metadata={"kind": "typing"},
        )

        with patch.object(chain, "_record_user_message"), patch.object(
                chain, "_mark_message_processing_started", return_value=status
        ), patch.object(chain, "_handle_message_core"), patch.object(
                chain, "_mark_message_processing_finished"
        ) as finish_status:
            chain.handle_message(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                text="CALLBACK:sites:req-1:refresh",
                original_chat_id="-100",
            )

        finish_status.assert_called_once_with(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            status=status,
            original_message_id=None,
            original_chat_id="-100",
        )

    def test_chain_finishes_processing_through_module_interface(self):
        chain = MessageChain.__new__(MessageChain)
        status = MessageChain._ProcessingStatus(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            chat_id="-100",
            metadata={"kind": "typing"},
        )

        with patch.object(chain, "run_module") as run_module:
            chain._mark_message_processing_finished(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                status=status,
                original_chat_id="-100",
            )

        run_module.assert_called_once_with(
            "mark_message_processing_finished",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            message_id=None,
            chat_id="-100",
            status=status.to_dict(),
        )

    def test_agent_manager_defers_shared_typing_until_queued_task_finishes(self):
        async def _run():
            manager = AgentManager()
            queue = asyncio.Queue()
            first = _MessageTask(
                session_id="session-1",
                user_id="10001",
                message="第一条",
                processing_status={
                    "channel": MessageChannel.Telegram.value,
                    "source": "telegram-test",
                    "userid": "10001",
                    "chat_id": "-100",
                    "metadata": {"kind": "typing"},
                },
            )
            second = _MessageTask(
                session_id="session-1",
                user_id="10001",
                message="第二条",
                processing_status={
                    "channel": MessageChannel.Telegram.value,
                    "source": "telegram-test",
                    "userid": "10001",
                    "chat_id": "-100",
                    "metadata": {"kind": "typing"},
                },
            )
            await queue.put(second)

            with patch(
                    "app.agent._async_finish_processing_status",
                    new_callable=AsyncMock,
            ) as finish_status:
                await manager._finish_task_processing_status(
                    session_id="session-1",
                    task=first,
                    queue=queue,
                )
                finish_status.assert_not_awaited()
                self.assertEqual(
                    manager._deferred_processing_statuses["session-1"],
                    first.processing_status,
                )

                queue.get_nowait()
                await manager._finish_task_processing_status(
                    session_id="session-1",
                    task=second,
                    queue=queue,
                )

            finish_status.assert_awaited_once_with(
                second.processing_status, "10001"
            )
            self.assertNotIn("session-1", manager._deferred_processing_statuses)

        asyncio.run(_run())

    def test_agent_manager_closes_deferred_typing_when_next_task_has_no_status(self):
        async def _run():
            manager = AgentManager()
            queue = asyncio.Queue()
            first = _MessageTask(
                session_id="session-1",
                user_id="10001",
                message="第一条",
                processing_status={
                    "channel": MessageChannel.Telegram.value,
                    "source": "telegram-test",
                    "userid": "10001",
                    "chat_id": "-100",
                    "metadata": {"kind": "typing"},
                },
            )
            second = _MessageTask(
                session_id="session-1",
                user_id="10001",
                message="第二条",
                processing_status=None,
            )
            await queue.put(second)

            with patch(
                    "app.agent._async_finish_processing_status",
                    new_callable=AsyncMock,
            ) as finish_status:
                await manager._finish_task_processing_status(
                    session_id="session-1",
                    task=first,
                    queue=queue,
                )
                queue.get_nowait()
                await manager._finish_task_processing_status(
                    session_id="session-1",
                    task=second,
                    queue=queue,
                )

            finish_status.assert_awaited_once_with(
                first.processing_status, "10001"
            )
            self.assertNotIn("session-1", manager._deferred_processing_statuses)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
