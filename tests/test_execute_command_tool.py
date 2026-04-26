import asyncio
import shlex
import sys
import unittest

import langchain.agents as langchain_agents

if not hasattr(langchain_agents, "create_agent"):
    langchain_agents.create_agent = lambda *args, **kwargs: None

from app.agent.callback import StreamingHandler
from app.agent.tools.impl.execute_command import ExecuteCommandTool


class TestExecuteCommandTool(unittest.TestCase):
    @staticmethod
    def _build_python_command(script: str) -> str:
        return f"{shlex.quote(sys.executable)} -c '{script}'"

    @staticmethod
    def _build_streaming_tool() -> tuple[ExecuteCommandTool, StreamingHandler]:
        tool = ExecuteCommandTool(session_id="session-1", user_id="10001")
        handler = StreamingHandler()
        handler._streaming_enabled = True
        handler._flush_task = object()
        tool.set_stream_handler(handler)
        return tool, handler

    def test_run_streams_live_output_and_collects_result(self):
        tool, handler = self._build_streaming_tool()
        command = self._build_python_command(
            'import sys; print("out"); print("err", file=sys.stderr)'
        )

        result = asyncio.run(tool.run(command=command, timeout=5))
        live_output = asyncio.run(handler.take())

        self.assertIn("命令执行完成 (退出码: 0)", result)
        self.assertIn("标准输出:\nout", result)
        self.assertIn("错误输出:\nerr", result)
        self.assertIn("标准输出:\nout", live_output)
        self.assertIn("错误输出:\nerr", live_output)

    def test_run_timeout_keeps_partial_output(self):
        tool = ExecuteCommandTool(session_id="session-1", user_id="10001")
        command = self._build_python_command(
            'import sys,time; print("start"); sys.stdout.flush(); time.sleep(0.2)'
        )

        result = asyncio.run(tool.run(command=command, timeout=0.05))

        self.assertIn("命令执行超时", result)
        self.assertIn("标准输出:\nstart", result)


if __name__ == "__main__":
    unittest.main()
