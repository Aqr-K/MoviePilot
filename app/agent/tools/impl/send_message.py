"""发送消息工具"""

from typing import Optional

from app.agent.tools.base import MoviePilotTool
from app.log import logger


class SendMessageTool(MoviePilotTool):
    name: str = "send_message"
    description: str = "发送消息通知，向用户发送操作结果或重要信息。"

    async def _arun(self, message: str, explanation: str, message_type: Optional[str] = "info", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: message={message}, message_type={message_type}")
        try:
            self.send_tool_message(message, title=message_type)
            return "消息已发送。"
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return f"发送消息时发生错误: {str(e)}"
