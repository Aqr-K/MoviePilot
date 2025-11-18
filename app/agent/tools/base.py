"""MoviePilot工具基类"""
from abc import ABCMeta, abstractmethod
from typing import Callable, Any, Optional

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
        # 优先使用工具自定义的提示消息，如果没有则使用 explanation
        tool_message = self.get_tool_message(**kwargs)
        if not tool_message:
            explanation = kwargs.get("explanation")
            if explanation:
                tool_message = explanation
        
        if tool_message:
            formatted_message = f"⚙️ {tool_message} ⚙️"
            await self.send_tool_message(formatted_message)
        return await self.run(**kwargs)

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """
        获取工具执行时的友好提示消息
        
        子类可以重写此方法，根据实际参数生成个性化的提示消息。
        如果返回 None 或空字符串，将回退使用 explanation 参数。
        
        Args:
            **kwargs: 工具的所有参数（包括 explanation）
            
        Returns:
            str: 友好的提示消息，如果返回 None 或空字符串则使用 explanation
        """
        return None

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
            ),
            escape_markdown=False
        )
