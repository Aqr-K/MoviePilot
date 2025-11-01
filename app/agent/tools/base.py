"""MoviePilot工具基类"""

from langchain.tools import BaseTool
from pydantic import PrivateAttr

from app.chain import ChainBase
from app.schemas import Notification


class ToolChain(ChainBase):
    pass


class MoviePilotTool(BaseTool):
    """MoviePilot专用工具基类"""

    _session_id: str = PrivateAttr()
    _user_id: str = PrivateAttr()
    _channel: str = PrivateAttr(default=None)
    _source: str = PrivateAttr(default=None)
    _username: str = PrivateAttr(default=None)

    def __init__(self, session_id: str, user_id: str, **kwargs):
        super().__init__(**kwargs)
        self._session_id = session_id
        self._user_id = user_id

    def _run(self, **kwargs) -> str:
        raise NotImplementedError

    async def _arun(self, **kwargs) -> str:
        raise NotImplementedError

    def set_message_attr(self, channel: str, source: str, username: str):
        """设置消息属性"""
        self._channel = channel
        self._source = source
        self._username = username

    def send_tool_message(self, message: str, title: str = "执行工具"):
        """发送工具消息"""
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
