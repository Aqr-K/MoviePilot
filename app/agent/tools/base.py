import json
from abc import ABCMeta, abstractmethod
from typing import Any, Optional

from langchain_core.tools import BaseTool
from pydantic import PrivateAttr

from app.agent import StreamingHandler
from app.chain import ChainBase
from app.log import logger
from app.schemas import Notification


class ToolChain(ChainBase):
    pass


class MoviePilotTool(BaseTool, metaclass=ABCMeta):
    """
    MoviePilot专用工具基类（LangChain v1 / langchain_core）
    """

    _session_id: str = PrivateAttr()
    _user_id: str = PrivateAttr()
    _channel: Optional[str] = PrivateAttr(default=None)
    _source: Optional[str] = PrivateAttr(default=None)
    _username: Optional[str] = PrivateAttr(default=None)
    _stream_handler: Optional[StreamingHandler] = PrivateAttr(default=None)

    def __init__(self, session_id: str, user_id: str, **kwargs):
        super().__init__(**kwargs)
        self._session_id = session_id
        self._user_id = user_id

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("MoviePilotTool 只支持异步调用，请使用 _arun")

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        """
        异步运行工具，负责：
        1. 在工具调用前将流式消息推送给用户
        2. 持久化工具调用记录到会话记忆
        3. 调用具体工具逻辑（子类实现的 execute 方法）
        4. 持久化工具结果到会话记忆
        """
        # 获取工具执行提示消息
        tool_message = self.get_tool_message(**kwargs)
        if not tool_message:
            explanation = kwargs.get("explanation")
            if explanation:
                tool_message = explanation

        if self._stream_handler and self._stream_handler.is_streaming:
            # 流式渠道：工具消息直接追加到 buffer 中，与 Agent 文字合并为同一条流式消息
            if tool_message:
                self._stream_handler.emit(f"\n\n⚙️ => {tool_message}\n\n")
        else:
            # 非流式渠道：保持原有行为，取出 Agent 文字 + 工具消息合并独立发送
            agent_message = (
                await self._stream_handler.take() if self._stream_handler else ""
            )

            messages = []
            if agent_message:
                messages.append(agent_message)
            if tool_message:
                messages.append(f"⚙️ => {tool_message}")

            if messages:
                merged_message = "\n\n".join(messages)
                await self.send_tool_message(merged_message)

        logger.debug(f"Executing tool {self.name} with args: {kwargs}")

        # 执行具体工具逻辑
        try:
            result = await self.run(**kwargs)
            logger.debug(f"Tool {self.name} executed with result: {result}")
        except Exception as e:
            error_message = f"工具执行异常 ({type(e).__name__}): {str(e)}"
            logger.error(f"Tool {self.name} execution failed: {e}", exc_info=True)
            result = error_message

        # 格式化结果
        if isinstance(result, str):
            formatted_result = result
        elif isinstance(result, (int, float)):
            formatted_result = str(result)
        else:
            formatted_result = json.dumps(result, ensure_ascii=False, indent=2)

        return formatted_result

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """
        获取工具执行时的友好提示消息。

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
        """子类实现具体的工具执行逻辑"""
        raise NotImplementedError

    def set_message_attr(self, channel: str, source: str, username: str):
        """
        设置消息属性
        """
        self._channel = channel
        self._source = source
        self._username = username

    def set_stream_handler(self, stream_handler: StreamingHandler):
        """
        设置回调处理器
        """
        self._stream_handler = stream_handler

    async def send_tool_message(self, message: str, title: str = ""):
        """
        发送工具消息
        """
        await ToolChain().async_post_message(
            Notification(
                channel=self._channel,
                source=self._source,
                userid=self._user_id,
                username=self._username,
                title=title,
                text=message,
            )
        )
