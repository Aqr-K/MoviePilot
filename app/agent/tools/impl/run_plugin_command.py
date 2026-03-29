"""运行插件命令工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.event import eventmanager
from app.core.plugin import PluginManager
from app.log import logger
from app.schemas.types import EventType, MessageChannel


class RunPluginCommandInput(BaseModel):
    """运行插件命令工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )
    command: str = Field(
        ...,
        description="The slash command to execute, e.g. '/cookiecloud'. "
        "Must start with '/'. Can include arguments after the command, e.g. '/command arg1 arg2'. "
        "Use query_plugin_capabilities tool to discover available commands first.",
    )


class RunPluginCommandTool(MoviePilotTool):
    name: str = "run_plugin_command"
    description: str = (
        "Execute a plugin command by sending a CommandExcute event. "
        "Plugin commands are slash-commands (starting with '/') registered by plugins. "
        "Use the query_plugin_capabilities tool first to discover available commands and their descriptions. "
        "The command will be executed asynchronously. "
        "Note: This tool triggers the command execution but the actual processing happens in the background."
    )
    args_schema: Type[BaseModel] = RunPluginCommandInput
    require_admin: bool = True

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """生成友好的提示消息"""
        command = kwargs.get("command", "")
        return f"正在执行插件命令: {command}"

    async def run(self, command: str, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: command={command}")

        try:
            # 确保命令以 / 开头
            if not command.startswith("/"):
                command = f"/{command}"

            # 验证命令是否存在
            plugin_manager = PluginManager()
            registered_commands = plugin_manager.get_plugin_commands()
            cmd_name = command.split()[0]
            matched_command = None
            for cmd in registered_commands:
                if cmd.get("cmd") == cmd_name:
                    matched_command = cmd
                    break

            if not matched_command:
                # 列出可用命令帮助用户
                available_cmds = [
                    f"{cmd.get('cmd')} - {cmd.get('desc', '无描述')}"
                    for cmd in registered_commands
                ]
                result = {
                    "success": False,
                    "message": f"命令 {cmd_name} 不存在",
                }
                if available_cmds:
                    result["available_commands"] = available_cmds
                return json.dumps(result, ensure_ascii=False, indent=2)

            # 构建消息渠道，优先使用当前会话的渠道信息
            channel = None
            if self._channel:
                try:
                    channel = MessageChannel(self._channel)
                except (ValueError, KeyError):
                    channel = None

            # 发送命令执行事件，与 message.py 中的方式一致
            eventmanager.send_event(
                EventType.CommandExcute,
                {
                    "cmd": command,
                    "user": self._user_id,
                    "channel": channel,
                    "source": self._source,
                },
            )

            result = {
                "success": True,
                "message": f"命令 {cmd_name} 已触发执行",
                "command": command,
                "command_desc": matched_command.get("desc", ""),
                "plugin_id": matched_command.get("pid", ""),
            }
            return json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"执行插件命令失败: {e}", exc_info=True)
            return json.dumps(
                {"success": False, "message": f"执行插件命令时发生错误: {str(e)}"},
                ensure_ascii=False,
            )
