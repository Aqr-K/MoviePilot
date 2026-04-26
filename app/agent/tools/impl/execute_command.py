"""执行Shell命令工具"""

import asyncio
import codecs
from typing import Any, Dict, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger


class ExecuteCommandInput(BaseModel):
    """执行Shell命令工具的输入参数模型"""

    explanation: str = Field(
        ..., description="Clear explanation of why this command is being executed"
    )
    command: str = Field(..., description="The shell command to execute")
    timeout: Optional[int] = Field(
        60, description="Max execution time in seconds (default: 60)"
    )


class ExecuteCommandTool(MoviePilotTool):
    name: str = "execute_command"
    description: str = "Safely execute shell commands on the server. Useful for system maintenance, checking status, or running custom scripts. Includes timeout and output limits."
    args_schema: Type[BaseModel] = ExecuteCommandInput
    require_admin: bool = True
    RESULT_LIMIT = 3000
    STREAM_CAPTURE_LIMIT = 2000
    LIVE_OUTPUT_LIMIT = 1200

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据命令生成友好的提示消息"""
        command = kwargs.get("command", "")
        return f"执行系统命令: {command}"

    def _build_result(
        self,
        message: str,
        stdout_capture: Dict[str, Any],
        stderr_capture: Dict[str, Any],
    ) -> str:
        stdout_str = "".join(stdout_capture["chunks"]).strip()
        stderr_str = "".join(stderr_capture["chunks"]).strip()

        result = message
        if stdout_str:
            result += f"\n\n标准输出:\n{stdout_str}"
        if stderr_str:
            result += f"\n\n错误输出:\n{stderr_str}"
        if not stdout_str and not stderr_str:
            result += "\n\n(无输出内容)"

        was_truncated = stdout_capture["truncated"] or stderr_capture["truncated"]
        overflow_suffix = "\n\n...(输出内容过长，已截断)"
        if was_truncated or len(result) > self.RESULT_LIMIT:
            result = (
                result[: self.RESULT_LIMIT - len(overflow_suffix)] + overflow_suffix
            )
        return result

    def _append_capture(self, capture: Dict[str, Any], text: str):
        if not text:
            return

        remaining = self.STREAM_CAPTURE_LIMIT - capture["length"]
        if remaining <= 0:
            capture["truncated"] = True
            return

        fragment = text[:remaining]
        capture["chunks"].append(fragment)
        capture["length"] += len(fragment)
        if len(text) > remaining:
            capture["truncated"] = True

    def _should_emit_live_output(self) -> bool:
        return bool(
            self._stream_handler
            and self._stream_handler.is_streaming
            and self._stream_handler.is_auto_flushing
        )

    def _emit_live_output(
        self, text: str, stream_name: str, live_state: Dict[str, Any]
    ):
        if not text or not live_state["enabled"]:
            return

        header_key = f"{stream_name}_header_sent"
        prefix = ""
        if not live_state[header_key]:
            prefix = "标准输出:\n" if stream_name == "stdout" else "\n错误输出:\n"
            live_state[header_key] = True

        payload = prefix + text
        remaining = self.LIVE_OUTPUT_LIMIT - live_state["chars"]
        if remaining <= 0:
            if not live_state["truncated"]:
                self._stream_handler.emit("\n...(命令输出过长，停止实时展示)\n")
                live_state["truncated"] = True
            return

        fragment = payload[:remaining]
        if fragment:
            self._stream_handler.emit(fragment)
            live_state["chars"] += len(fragment)

        if len(payload) > remaining and not live_state["truncated"]:
            self._stream_handler.emit("\n...(命令输出过长，停止实时展示)\n")
            live_state["truncated"] = True

    async def _collect_stream(
        self,
        stream: Optional[asyncio.StreamReader],
        stream_name: str,
        capture: Dict[str, Any],
        live_state: Dict[str, Any],
    ):
        if not stream:
            return

        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            chunk = await stream.read(512)
            if not chunk:
                tail = decoder.decode(b"", final=True)
                if tail:
                    self._append_capture(capture, tail)
                    self._emit_live_output(tail, stream_name, live_state)
                return

            text = decoder.decode(chunk)
            if not text:
                continue

            self._append_capture(capture, text)
            self._emit_live_output(text, stream_name, live_state)

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process):
        if process.returncode is not None:
            return

        try:
            process.kill()
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            logger.warning("终止命令进程超时")

    async def run(self, command: str, timeout: Optional[int] = 60, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: command={command}, timeout={timeout}"
        )

        # 简单安全过滤
        forbidden_keywords = [
            "rm -rf /",
            ":(){ :|:& };:",
            "dd if=/dev/zero",
            "mkfs",
            "reboot",
            "shutdown",
        ]
        for keyword in forbidden_keywords:
            if keyword in command:
                return f"错误：命令包含禁止使用的关键字 '{keyword}'"

        try:
            # 执行命令
            process = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout_capture: Dict[str, Any] = {
                "chunks": [],
                "length": 0,
                "truncated": False,
            }
            stderr_capture: Dict[str, Any] = {
                "chunks": [],
                "length": 0,
                "truncated": False,
            }
            live_state: Dict[str, Any] = {
                "enabled": self._should_emit_live_output(),
                "chars": 0,
                "truncated": False,
                "stdout_header_sent": False,
                "stderr_header_sent": False,
            }

            stdout_task = asyncio.create_task(
                self._collect_stream(
                    process.stdout, "stdout", stdout_capture, live_state
                )
            )
            stderr_task = asyncio.create_task(
                self._collect_stream(
                    process.stderr, "stderr", stderr_capture, live_state
                )
            )

            try:
                # 等待完成，带超时
                await asyncio.wait_for(process.wait(), timeout=timeout)
                await asyncio.gather(stdout_task, stderr_task)
                return self._build_result(
                    f"命令执行完成 (退出码: {process.returncode})",
                    stdout_capture,
                    stderr_capture,
                )

            except asyncio.TimeoutError:
                # 超时处理
                await self._terminate_process(process)
                await asyncio.gather(stdout_task, stderr_task)
                return self._build_result(
                    f"命令执行超时 (限制: {timeout}秒)",
                    stdout_capture,
                    stderr_capture,
                )

        except Exception as e:
            logger.error(f"执行命令失败: {e}", exc_info=True)
            return f"执行命令时发生错误: {str(e)}"
