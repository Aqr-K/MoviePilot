import asyncio
import os
import shlex
import subprocess
import sys
import time
import unittest

from app.agent.tools.impl.execute_command import (
    ExecuteCommandTool,
    MAX_OUTPUT_CHARS,
)


def _python_command(code: str) -> str:
    """生成当前解释器可执行的 shell 命令，避免依赖系统 python 名称。"""
    args = [sys.executable, "-c", code]
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(arg) for arg in args)


class TestExecuteCommandTool(unittest.TestCase):
    def _run_command(self, command: str, timeout: int = 60) -> str:
        tool = ExecuteCommandTool(session_id="session-1", user_id="10001")
        return asyncio.run(tool.run(command=command, timeout=timeout))

    def test_large_output_is_truncated_before_returning_to_agent(self):
        command = _python_command(
            "import sys; sys.stdout.write('x' * 200000); sys.stdout.flush()"
        )

        result = self._run_command(command)

        self.assertIn("输出内容过长，已截断", result)
        self.assertLess(len(result), MAX_OUTPUT_CHARS + 500)

    def test_timeout_returns_partial_output_promptly(self):
        command = _python_command(
            "import time; print('started', flush=True); time.sleep(5)"
        )

        started_at = time.monotonic()
        result = self._run_command(command, timeout=1)
        duration = time.monotonic() - started_at

        self.assertLess(duration, 4)
        self.assertIn("命令执行超时", result)
        self.assertIn("started", result)

    def test_timeout_is_capped(self):
        command = _python_command("print('ok')")

        result = self._run_command(command, timeout=9999)

        self.assertIn("timeout 参数超过上限", result)
        self.assertIn("ok", result)


if __name__ == "__main__":
    unittest.main()
