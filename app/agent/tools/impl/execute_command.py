"""执行Shell命令工具"""

import asyncio
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger


class ExecuteCommandInput(BaseModel):
    """执行Shell命令工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this command is being executed")
    command: str = Field(..., description="The shell command to execute")
    timeout: Optional[int] = Field(60, description="Max execution time in seconds (default: 60)")


class ExecuteCommandTool(MoviePilotTool):
    name: str = "execute_command"
    description: str = "Safely execute shell commands on the server. Useful for system maintenance, checking status, or running custom scripts. Includes timeout and output limits."
    args_schema: Type[BaseModel] = ExecuteCommandInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据命令生成友好的提示消息"""
        command = kwargs.get("command", "")
        return f"正在执行系统命令: {command}"

    async def run(self, command: str, timeout: Optional[int] = 60, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: command={command}, timeout={timeout}")

        # 简单安全过滤
        forbidden_keywords = ["rm -rf /", ":(){ :|:& };:", "dd if=/dev/zero", "mkfs", "reboot", "shutdown"]
        for keyword in forbidden_keywords:
            if keyword in command:
                return f"错误：命令包含禁止使用的关键字 '{keyword}'"

        try:
            # 执行命令
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                # 等待完成，带超时
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                # 处理输出
                stdout_str = stdout.decode('utf-8', errors='replace').strip()
                stderr_str = stderr.decode('utf-8', errors='replace').strip()
                exit_code = process.returncode

                result = f"命令执行完成 (退出码: {exit_code})"
                if stdout_str:
                    result += f"\n\n标准输出:\n{stdout_str}"
                if stderr_str:
                    result += f"\n\n错误输出:\n{stderr_str}"
                
                # 如果没有输出
                if not stdout_str and not stderr_str:
                    result += "\n\n(无输出内容)"
                
                # 限制输出长度，防止上下文过长
                if len(result) > 3000:
                    result = result[:3000] + "\n\n...(输出内容过长，已截断)"
                
                return result

            except asyncio.TimeoutError:
                # 超时处理
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                return f"命令执行超时 (限制: {timeout}秒)"

        except Exception as e:
            logger.error(f"执行命令失败: {e}", exc_info=True)
            return f"执行命令时发生错误: {str(e)}"
