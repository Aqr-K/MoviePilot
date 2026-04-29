import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from app.agent import MoviePilotAgent, AgentManager, ReplyMode
from app.agent.memory import memory_manager
from app.utils.identity import SYSTEM_INTERNAL_USER_ID


class _FakeGraphState:
    def __init__(self, messages):
        self.values = {"messages": messages}


class _FakeAgent:
    def __init__(self, messages):
        self._messages = messages

    async def ainvoke(self, _payload, config=None):
        return None

    def get_state(self, _config):
        return _FakeGraphState(self._messages)


class AgentBackgroundOutputTest(unittest.IsolatedAsyncioTestCase):
    async def test_background_non_streaming_does_not_send_by_default(self):
        agent = MoviePilotAgent(session_id="bg-test", user_id="system")
        agent.channel = None
        agent.source = None
        agent.reply_mode = ReplyMode.CAPTURE_ONLY
        agent.persist_output_message = True
        agent._tool_context = {"user_reply_sent": False}
        agent._streamed_output = ""
        agent.stream_handler = SimpleNamespace(
            stop_streaming=AsyncMock(return_value=(False, ""))
        )
        agent._should_stream = lambda: False
        agent._create_agent = lambda streaming=False: _FakeAgent(
            [AIMessage(content="后台结果")]
        )
        agent.send_agent_message = AsyncMock()
        agent._save_agent_message_to_db = AsyncMock()

        with patch.object(memory_manager, "save_agent_messages") as save_messages:
            await agent._execute_agent([])

        agent.send_agent_message.assert_not_awaited()
        agent._save_agent_message_to_db.assert_awaited_once_with(
            "后台结果", title="MoviePilot助手"
        )
        save_messages.assert_called_once()
        self.assertEqual("后台结果", agent._streamed_output)

    async def test_background_non_streaming_sends_when_reply_mode_dispatch(self):
        agent = MoviePilotAgent(session_id="bg-test", user_id="system")
        agent.channel = None
        agent.source = None
        agent.reply_mode = ReplyMode.DISPATCH
        agent.persist_output_message = False
        agent._tool_context = {"user_reply_sent": False}
        agent._streamed_output = ""
        agent.stream_handler = SimpleNamespace(
            stop_streaming=AsyncMock(return_value=(False, ""))
        )
        agent._should_stream = lambda: False
        agent._create_agent = lambda streaming=False: _FakeAgent(
            [AIMessage(content="后台结果")]
        )
        agent.send_agent_message = AsyncMock()
        agent._save_agent_message_to_db = AsyncMock()

        with patch.object(memory_manager, "save_agent_messages") as save_messages:
            await agent._execute_agent([])

        agent.send_agent_message.assert_awaited_once_with(
            "后台结果", title="MoviePilot助手"
        )
        agent._save_agent_message_to_db.assert_not_awaited()
        save_messages.assert_called_once()
        self.assertEqual("后台结果", agent._streamed_output)

    async def test_background_non_streaming_persists_without_sending_when_capture_only(self):
        agent = MoviePilotAgent(session_id="bg-test", user_id="system")
        agent.channel = None
        agent.source = None
        agent.reply_mode = ReplyMode.CAPTURE_ONLY
        agent.persist_output_message = True
        agent._tool_context = {"user_reply_sent": False}
        agent._streamed_output = ""
        agent.stream_handler = SimpleNamespace(
            stop_streaming=AsyncMock(return_value=(False, ""))
        )
        agent._should_stream = lambda: False
        agent._create_agent = lambda streaming=False: _FakeAgent(
            [AIMessage(content="后台结果")]
        )
        agent.send_agent_message = AsyncMock()
        agent._save_agent_message_to_db = AsyncMock()

        with patch.object(memory_manager, "save_agent_messages") as save_messages:
            await agent._execute_agent([])

        agent.send_agent_message.assert_not_awaited()
        agent._save_agent_message_to_db.assert_awaited_once_with(
            "后台结果", title="MoviePilot助手"
        )
        save_messages.assert_called_once()
        self.assertEqual("后台结果", agent._streamed_output)

    async def test_heartbeat_check_jobs_uses_dispatch_reply_mode(self):
        manager = AgentManager()

        with (
            patch.object(manager, "_build_heartbeat_prompt", return_value="HEARTBEAT"),
            patch.object(manager, "process_message", new=AsyncMock()) as process_message,
        ):
            await manager.heartbeat_check_jobs()

        process_message.assert_awaited_once()
        self.assertEqual(
            ReplyMode.DISPATCH,
            process_message.await_args.kwargs["reply_mode"],
        )

    async def test_run_background_prompt_forces_disable_message_tools_when_capture_only(self):
        captured = {}

        async def fake_process(self, message, images=None, files=None):
            captured["message"] = message
            captured["reply_mode"] = self.reply_mode
            captured["allow_message_tools"] = self.allow_message_tools
            captured["user_id"] = self.user_id

        with (
            patch.object(MoviePilotAgent, "process", new=fake_process),
            patch.object(MoviePilotAgent, "cleanup", new=AsyncMock()),
            patch.object(memory_manager, "clear_memory"),
        ):
            await AgentManager.run_background_prompt(
                message="background task",
                reply_mode=ReplyMode.CAPTURE_ONLY,
                allow_message_tools=True,
            )

        self.assertEqual("background task", captured["message"])
        self.assertEqual(ReplyMode.CAPTURE_ONLY, captured["reply_mode"])
        self.assertFalse(captured["allow_message_tools"])
        self.assertEqual(SYSTEM_INTERNAL_USER_ID, captured["user_id"])


if __name__ == "__main__":
    unittest.main()
