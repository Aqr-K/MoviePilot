import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from app.agent import MoviePilotAgent
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
    async def test_background_non_streaming_skips_send_when_output_persistence_disabled(self):
        agent = MoviePilotAgent(session_id="bg-test", user_id="system")
        agent.channel = None
        agent.source = None
        agent.suppress_user_reply = False
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

        with patch.object(memory_manager, "save_agent_messages") as save_messages:
            await agent._execute_agent([])

        agent.send_agent_message.assert_not_awaited()
        save_messages.assert_called_once()
        self.assertEqual("后台结果", agent._streamed_output)


if __name__ == "__main__":
    unittest.main()
