import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from app.agent import MoviePilotAgent, AgentManager, ReplyMode
from app.agent.memory import memory_manager


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


if __name__ == "__main__":
    unittest.main()
