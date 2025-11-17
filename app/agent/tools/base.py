"""MoviePilot工具基类"""
from abc import ABCMeta, abstractmethod
from typing import Callable, Any

from langchain.tools import BaseTool
from pydantic import PrivateAttr

from app.agent import StreamingCallbackHandler
from app.chain import ChainBase
from app.schemas import Notification


class ToolChain(ChainBase):
    pass


class MoviePilotTool(BaseTool, metaclass=ABCMeta):
    """MoviePilot专用工具基类"""

    _session_id: str = PrivateAttr()
    _user_id: str = PrivateAttr()
    _channel: str = PrivateAttr(default=None)
    _source: str = PrivateAttr(default=None)
    _username: str = PrivateAttr(default=None)
    _callback_handler: StreamingCallbackHandler = PrivateAttr(default=None)

    def __init__(self, session_id: str, user_id: str, **kwargs):
        super().__init__(**kwargs)
        self._session_id = session_id
        self._user_id = user_id

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        pass

    async def _arun(self, **kwargs) -> str:
        """异步运行工具"""
        # 发送运行工具前的消息
        agent_message = await self._callback_handler.get_message()
        if agent_message:
            await self.send_tool_message(agent_message, title="MoviePilot助手")
        # 发送执行工具说明
        explanation = kwargs.get("explanation")
        if explanation:
            await self.send_tool_message(f"▶️️{explanation}")
        return await self.run(**kwargs)

    @abstractmethod
    async def run(self, **kwargs) -> str:
        raise NotImplementedError

    def set_message_attr(self, channel: str, source: str, username: str):
        """设置消息属性"""
        self._channel = channel
        self._source = source
        self._username = username

    def set_callback_handler(self, callback_handler: StreamingCallbackHandler):
        """设置回调处理器"""
        self._callback_handler = callback_handler

    async def send_tool_message(self, message: str, title: str = ""):
        """发送工具消息"""
        await ToolChain().async_post_message(
            Notification(
                channel=self._channel,
                source=self._source,
                userid=self._user_id,
                username=self._username,
                title=title,
                text=message
            )
        )
