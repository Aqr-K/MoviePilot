import threading

from langchain_core.callbacks import AsyncCallbackHandler

from app.log import logger


class StreamingCallbackHandler(AsyncCallbackHandler):
    """
    流式输出回调处理器
    """

    def __init__(self, session_id: str):
        self._lock = threading.Lock()
        self.session_id = session_id
        self.current_message = ""

    async def get_message(self):
        """
        获取当前消息内容，获取后清空
        """
        with self._lock:
            if not self.current_message:
                return ""
            msg = self.current_message
            logger.info(f"Agent消息: {msg}")
            self.current_message = ""
            return msg

    async def on_llm_new_token(self, token: str, **kwargs):
        """
        处理新的token
        """
        if not token:
            return
        with self._lock:
            # 缓存当前消息
            self.current_message += token

