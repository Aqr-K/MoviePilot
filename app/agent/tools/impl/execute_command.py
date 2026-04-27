"""执行Shell命令工具"""

import asyncio
import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger


DEFAULT_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_CHARS = 6000
READ_CHUNK_SIZE = 4096
KILL_GRACE_SECONDS = 3
COMMAND_CONCURRENCY_LIMIT = 2

_command_semaphore = asyncio.Semaphore(COMMAND_CONCURRENCY_LIMIT)


@dataclass
class _CommandOutput:
    """保存受限命令输出，避免大输出一次性进入内存。"""

    limit: int
    stdout_chunks: list[str] = field(default_factory=list)
    stderr_chunks: list[str] = field(default_factory=list)
    captured_chars: int = 0
    truncated: bool = False

    def append(self, stream_name: str, text: str) -> None:
        if not text:
            return

        remaining = self.limit - self.captured_chars
        if remaining <= 0:
            self.truncated = True
            return

        captured = text[:remaining]
        if stream_name == "stdout":
            self.stdout_chunks.append(captured)
        else:
            self.stderr_chunks.append(captured)

        self.captured_chars += len(captured)
        if len(text) > remaining:
            self.truncated = True

    @property
    def stdout(self) -> str:
        return "".join(self.stdout_chunks).strip()

    @property
    def stderr(self) -> str:
        return "".join(self.stderr_chunks).strip()


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
    description: str = (
        "Safely execute shell commands on the server. Useful for system "
        "maintenance, checking status, or running custom scripts. Includes "
        "timeout, concurrency, and hard output limits."
    )
    args_schema: Type[BaseModel] = ExecuteCommandInput
    require_admin: bool = True

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据命令生成友好的提示消息"""
        command = kwargs.get("command", "")
        return f"执行系统命令: {command}"

    @staticmethod
    def _normalize_timeout(timeout: Optional[int]) -> tuple[int, Optional[str]]:
        """限制命令最长运行时间，避免 Agent 传入过大的 timeout。"""
        try:
            normalized = int(timeout or DEFAULT_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            normalized = DEFAULT_TIMEOUT_SECONDS

        if normalized <= 0:
            return DEFAULT_TIMEOUT_SECONDS, "timeout 参数无效，已使用默认 60 秒"
        if normalized > MAX_TIMEOUT_SECONDS:
            return (
                MAX_TIMEOUT_SECONDS,
                f"timeout 参数超过上限，已从 {normalized} 秒限制为 {MAX_TIMEOUT_SECONDS} 秒",
            )
        return normalized, None

    @staticmethod
    def _subprocess_kwargs() -> dict:
        """为子进程创建独立进程组，便于超时或输出过大时清理整棵子进程。"""
        kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        elif os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        return kwargs

    @staticmethod
    async def _read_stream(
        stream: asyncio.StreamReader,
        stream_name: str,
        output: _CommandOutput,
        limit_reached: asyncio.Event,
    ) -> None:
        """按块读取输出，达到上限后通知主流程终止命令。"""
        while True:
            chunk = await stream.read(READ_CHUNK_SIZE)
            if not chunk:
                break

            if output.truncated:
                limit_reached.set()
                continue

            output.append(stream_name, chunk.decode("utf-8", errors="replace"))
            if output.truncated:
                limit_reached.set()
                # 达到上限后继续排空管道但不再保存内容，避免子进程因 pipe 反压卡住。
                continue

    @staticmethod
    def _terminate_process(process: asyncio.subprocess.Process, sig: int):
        """向进程组发送终止信号；不支持进程组的平台回退为单进程终止。"""
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            elif sig == getattr(signal, "SIGKILL", None):
                process.kill()
            else:
                process.terminate()
        except ProcessLookupError:
            pass

    @classmethod
    async def _cleanup_process(
        cls,
        process: asyncio.subprocess.Process,
        wait_task: asyncio.Task,
    ) -> None:
        """先温和终止，失败后强杀，避免超时 shell 遗留子进程。"""
        if wait_task.done():
            return

        cls._terminate_process(process, signal.SIGTERM)
        try:
            await asyncio.wait_for(
                asyncio.shield(wait_task), timeout=KILL_GRACE_SECONDS
            )
            return
        except asyncio.TimeoutError:
            pass

        kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
        cls._terminate_process(process, kill_signal)
        try:
            await asyncio.wait_for(
                asyncio.shield(wait_task), timeout=KILL_GRACE_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning("命令进程强制清理超时: pid=%s", process.pid)

    @staticmethod
    async def _finish_reader_tasks(reader_tasks: list[asyncio.Task]) -> None:
        """等待输出读取任务退出，异常只记录不影响工具返回。"""
        if not reader_tasks:
            return
        done, pending = await asyncio.wait(reader_tasks, timeout=1)
        for task in pending:
            task.cancel()
        results = await asyncio.gather(*done, *pending, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception) and not isinstance(
                result, asyncio.CancelledError
            ):
                logger.debug("命令输出读取任务异常: %s", result)

    @staticmethod
    def _format_result(
        *,
        exit_code: Optional[int],
        output: _CommandOutput,
        timeout: int,
        timed_out: bool,
        output_limited: bool,
        timeout_note: Optional[str],
    ) -> str:
        if timed_out:
            result = f"命令执行超时 (限制: {timeout}秒，已终止进程)"
        elif output_limited:
            result = (
                f"命令输出超过限制 (限制: {MAX_OUTPUT_CHARS}字符，"
                f"已截断并终止进程，退出码: {exit_code})"
            )
        else:
            result = f"命令执行完成 (退出码: {exit_code})"

        if timeout_note:
            result += f"\n\n提示:\n{timeout_note}"
        if output.stdout:
            result += f"\n\n标准输出:\n{output.stdout}"
        if output.stderr:
            result += f"\n\n错误输出:\n{output.stderr}"
        if output.truncated:
            result += "\n\n...(输出内容过长，已截断)"
        if not output.stdout and not output.stderr:
            result += "\n\n(无输出内容)"
        return result

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

        normalized_timeout, timeout_note = self._normalize_timeout(timeout)

        try:
            async with _command_semaphore:
                # 命令输出可能非常大，必须边读边截断，不能使用 communicate() 一次性收集。
                process = await asyncio.create_subprocess_shell(
                    command, **self._subprocess_kwargs()
                )
                output = _CommandOutput(limit=MAX_OUTPUT_CHARS)
                limit_reached = asyncio.Event()
                wait_task = asyncio.create_task(process.wait())
                limit_task = asyncio.create_task(limit_reached.wait())
                reader_tasks = [
                    asyncio.create_task(
                        self._read_stream(
                            process.stdout, "stdout", output, limit_reached
                        )
                    ),
                    asyncio.create_task(
                        self._read_stream(
                            process.stderr, "stderr", output, limit_reached
                        )
                    ),
                ]

                timed_out = False
                output_limited = False
                done, _ = await asyncio.wait(
                    {wait_task, limit_task},
                    timeout=normalized_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if wait_task not in done:
                    if limit_task in done:
                        output_limited = True
                    else:
                        timed_out = True
                    await self._cleanup_process(process, wait_task)

                limit_task.cancel()
                await self._finish_reader_tasks(reader_tasks)

                return self._format_result(
                    exit_code=process.returncode,
                    output=output,
                    timeout=normalized_timeout,
                    timed_out=timed_out,
                    output_limited=output_limited,
                    timeout_note=timeout_note,
                )

        except Exception as e:
            logger.error(f"执行命令失败: {e}", exc_info=True)
            return f"执行命令时发生错误: {str(e)}"
