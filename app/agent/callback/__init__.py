import threading

from app.log import logger


class StreamingHandler:
    """
    流式Token缓冲管理器

    负责从 LLM 流式 token 中积累文本，供 Agent 在工具调用之间穿插发送中间消息。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer = ""

    def emit(self, token: str):
        """
        接收 LLM 流式 token，积累到缓冲区。
        """
        with self._lock:
            self._buffer += token

    def take(self) -> str:
        """
        获取当前已积累的消息内容，获取后清空缓冲区。
        """
        with self._lock:
            if not self._buffer:
                return ""
            message = self._buffer
            logger.info(f"Agent消息: {message}")
            self._buffer = ""
            return message

    def clear(self):
        """
        清空缓冲区（不返回内容）
        """
        with self._lock:
            self._buffer = ""
