import json
import uuid
from abc import ABCMeta, abstractmethod
from typing import Any, Optional

from langchain.tools import BaseTool
from pydantic import PrivateAttr

from app.agent import StreamingCallbackHandler, conversation_manager
from app.chain import ChainBase
from app.log import logger
from app.schemas import Notification


class ToolChain(ChainBase):
    pass


class MoviePilotTool(BaseTool, metaclass=ABCMeta):
    """
    MoviePilot专用工具基类
    """

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
        """
        异步运行工具
        """
        # 获取工具调用前的agent消息
        agent_message = await self._callback_handler.get_message()

        # 生成唯一的工具调用ID
        call_id = f"call_{str(uuid.uuid4())[:16]}"

        # 记忆工具调用
        await conversation_manager.add_conversation(
            session_id=self._session_id,
            user_id=self._user_id,
            role="tool_call",
            content=agent_message,
            metadata={
                "call_id": call_id,
                "tool_name": self.name,
                "parameters": kwargs
            }
        )

        # 获取执行工具说明,优先使用工具自定义的提示消息，如果没有则使用 explanation
        tool_message = self.get_tool_message(**kwargs)
        if not tool_message:
            explanation = kwargs.get("explanation")
            if explanation:
                tool_message = explanation

        # 合并agent消息和工具执行消息，一起发送
        messages = []
        if agent_message:
            messages.append(agent_message)
        if tool_message:
            messages.append(f"⚙️ => {tool_message}")

        # 发送合并后的消息
        if messages:
            merged_message = "\n\n".join(messages)
            await self.send_tool_message(merged_message, title="MoviePilot助手")

        logger.debug(f'Executing tool {self.name} with args: {kwargs}')

        # 执行工具，捕获异常确保结果总是被存储到记忆中
        try:
            result = await self.run(**kwargs)
            logger.debug(f'Tool {self.name} executed with result: {result}')
        except Exception as e:
            # 记录异常详情
            error_message = f"工具执行异常 ({type(e).__name__}): {str(e)}"
            logger.error(f'Tool {self.name} execution failed: {e}', exc_info=True)
            result = error_message

        # 记忆工具调用结果
        if isinstance(result, str):
            formated_result = result
        elif isinstance(result, (int, float)):
            formated_result = str(result)
        else:
            formated_result = json.dumps(result, ensure_ascii=False, indent=2)

        await conversation_manager.add_conversation(
            session_id=self._session_id,
            user_id=self._user_id,
            role="tool_result",
            content=formated_result,
            metadata={
                "call_id": call_id,
                "tool_name": self.name,
            }
        )

        return result

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
        """
        设置消息属性
        """
        self._channel = channel
        self._source = source
        self._username = username

    def set_callback_handler(self, callback_handler: StreamingCallbackHandler):
        """
        设置回调处理器
        """
        self._callback_handler = callback_handler

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
                text=message
            )
        )
