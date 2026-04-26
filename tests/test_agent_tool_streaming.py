import asyncio
import unittest
from unittest.mock import patch

from app.agent.callback import StreamingHandler
from app.agent.tools.base import MoviePilotTool
from app.core.config import settings


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


if __name__ == "__main__":
    unittest.main()
