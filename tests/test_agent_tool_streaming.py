import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import langchain.agents as langchain_agents

if not hasattr(langchain_agents, "create_agent"):
    langchain_agents.create_agent = lambda *args, **kwargs: None

from app.agent.callback import StreamingHandler
from app.agent.tools.base import MoviePilotTool
from app.core.config import settings
from app.schemas.message import MessageResponse
from app.schemas.types import MessageChannel


class DummyTool(MoviePilotTool):
    name: str = "dummy_tool"
    description: str = "Dummy tool for streaming tests."

    async def run(self, **kwargs) -> str:
        return "ok"


class TestAgentToolStreaming(unittest.TestCase):
    async def _run_tool(self, initial_buffer: str) -> tuple[str, str]:
        tool = DummyTool(session_id="session-1", user_id="10001")
        handler = StreamingHandler()
        await handler.start_streaming()
        if initial_buffer:
            handler.emit(initial_buffer)
        tool.set_stream_handler(handler)

        with patch.object(settings, "AI_AGENT_VERBOSE", False):
            result = await tool._arun(explanation="run test tool")

        buffered_message = await handler.take()
        return result, buffered_message

    def test_non_verbose_tool_call_appends_newline_separator(self):
        result, buffered_message = asyncio.run(self._run_tool("prefix"))

        self.assertEqual(result, "ok")
        self.assertEqual(buffered_message, "prefix\n")

    def test_non_verbose_tool_call_does_not_duplicate_newline(self):
        result, buffered_message = asyncio.run(self._run_tool("prefix\n"))

        self.assertEqual(result, "ok")
        self.assertEqual(buffered_message, "prefix\n")

    def test_non_verbose_tool_call_keeps_empty_buffer_unchanged(self):
        result, buffered_message = asyncio.run(self._run_tool(""))

        self.assertEqual(result, "ok")
        self.assertEqual(buffered_message, "")

    def test_flush_sends_direct_message_via_threadpool(self):
        handler = StreamingHandler()
        handler._channel = MessageChannel.Telegram.value
        handler._source = "telegram"
        handler._user_id = "10001"
        handler._username = "tester"
        handler._streaming_enabled = True
        handler.emit("hello")

        with patch(
            "app.agent.callback.run_in_threadpool", new_callable=AsyncMock
        ) as run_in_threadpool_mock:
            run_in_threadpool_mock.return_value = MessageResponse(
                message_id=1,
                chat_id=2,
                source="telegram",
                success=True,
            )

            asyncio.run(handler._flush())

        self.assertEqual(run_in_threadpool_mock.await_count, 1)
        self.assertEqual(
            run_in_threadpool_mock.await_args.args[0].__name__, "send_direct_message"
        )
        self.assertTrue(handler.has_sent_message)

    def test_flush_edits_message_via_threadpool(self):
        handler = StreamingHandler()
        handler._channel = MessageChannel.Telegram.value
        handler._streaming_enabled = True
        handler._message_response = MessageResponse(
            message_id=1,
            chat_id=2,
            source="telegram",
            success=True,
        )
        handler._sent_text = "hello"
        handler.emit("hello world")

        with patch(
            "app.agent.callback.run_in_threadpool", new_callable=AsyncMock
        ) as run_in_threadpool_mock:
            run_in_threadpool_mock.return_value = True

            asyncio.run(handler._flush())

        self.assertEqual(run_in_threadpool_mock.await_count, 1)
        self.assertEqual(
            run_in_threadpool_mock.await_args.args[0].__name__, "edit_message"
        )
        self.assertEqual(handler._sent_text, "hello world")


if __name__ == "__main__":
    unittest.main()
