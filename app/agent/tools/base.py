"""MoviePilot工具基类"""

from langchain.tools import BaseTool
from pydantic import PrivateAttr

from app.helper.message import MessageHelper
from app.log import logger


class MoviePilotTool(BaseTool):
    """MoviePilot专用工具基类"""

    _session_id: str = PrivateAttr()
    _user_id: str = PrivateAttr()
    _message_helper: MessageHelper = PrivateAttr()

    def __init__(self, session_id: str, user_id: str, message_helper: MessageHelper = None, **kwargs):
        super().__init__(**kwargs)
        self._session_id = session_id
        self._user_id = user_id
        self._message_helper = message_helper or MessageHelper()

    def _run(self, **kwargs) -> str:
        raise NotImplementedError

    async def _arun(self, **kwargs) -> str:
        raise NotImplementedError

    def _send_tool_message(self, message: str, message_type: str = "info"):
        """发送工具执行消息"""
        try:
            self._message_helper.put(
                message=message,
                role="system",
                title=f"AI工具执行 ({message_type})"
            )
        except Exception as e:
            logger.error(f"发送工具消息失败: {e}")
