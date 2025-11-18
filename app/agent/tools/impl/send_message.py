"""发送消息工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger


class SendMessageInput(BaseModel):
    """发送消息工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    message: str = Field(..., description="The message content to send to the user (should be clear and informative)")
    message_type: Optional[str] = Field("info",
                                        description="Type of message: 'info' for general information, 'success' for successful operations, 'warning' for warnings, 'error' for error messages")


class SendMessageTool(MoviePilotTool):
    name: str = "send_message"
    description: str = "Send notification message to the user through configured notification channels (Telegram, Slack, WeChat, etc.). Used to inform users about operation results, errors, or important updates."
    args_schema: Type[BaseModel] = SendMessageInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据消息参数生成友好的提示消息"""
        message = kwargs.get("message", "")
        message_type = kwargs.get("message_type", "info")
        
        type_map = {"info": "信息", "success": "成功", "warning": "警告", "error": "错误"}
        type_desc = type_map.get(message_type, message_type)
        
        # 截断过长的消息
        if len(message) > 50:
            message = message[:50] + "..."
        
        return f"正在发送{type_desc}消息: {message}"

    async def run(self, message: str, message_type: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: message={message}, message_type={message_type}")
        try:
            await self.send_tool_message(message, title=message_type)
            return "消息已发送"
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return f"发送消息时发生错误: {str(e)}"
