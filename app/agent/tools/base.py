"""MoviePilot工具基类"""

from langchain.tools import BaseTool
from pydantic import PrivateAttr

from app.chain import ChainBase
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import Notification


class ToolChain(ChainBase):
    pass


class MoviePilotTool(BaseTool):
    """MoviePilot专用工具基类"""

    _session_id: str = PrivateAttr()
    _user_id: str = PrivateAttr()
    _message_helper: MessageHelper = PrivateAttr()

    def __init__(self, session_id: str, user_id: str,
                 channel: str = None, source: str = None, username: str = None, **kwargs):
        super().__init__(**kwargs)
        self._session_id = session_id
        self._user_id = user_id
        self.channel = channel
        self.source = source
        self.username = username
        self._message_helper = MessageHelper()

    def _run(self, **kwargs) -> str:
        raise NotImplementedError

    async def _arun(self, **kwargs) -> str:
        raise NotImplementedError

    def _send_tool_message(self, message: str, title: str = None, **kwargs):
        """发送工具执行消息"""
        ToolChain().post_message(
            Notification(
                channel=self.channel,
                source=self.source,
                userid=self.user_id,
                username=self.username,
                title=title,
                text=message
            )
        )
