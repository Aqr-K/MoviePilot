"""发送消息工具"""

from typing import Optional

from app.helper.message import MessageHelper
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class SendMessageTool(MoviePilotTool):
    name: str = "send_message"
    description: str = "发送消息通知，向用户发送操作结果或重要信息。"

    async def _arun(self, message: str, explanation: str, message_type: Optional[str] = "info") -> str:
        logger.info(f"执行工具: {self.name}, 参数: message={message}, message_type={message_type}")
        try:
            message_helper = MessageHelper()
            message_helper.put(message=message, role="system", title=f"AI助手通知 ({message_type})")
            return "消息已发送。"
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return f"发送消息时发生错误: {str(e)}"
