import asyncio
import threading
from typing import Optional

from app.chain import ChainBase
from app.log import logger
from app.schemas import Notification
from app.schemas.message import (
    MessageResponse,
    ChannelCapabilityManager,
    ChannelCapability,
)
from app.schemas.types import MessageChannel


class _StreamChain(ChainBase):
    pass


class StreamingHandler:
    """
    流式Token缓冲管理器

    负责从 LLM 流式 token 中积累文本，供 Agent 在工具调用之间穿插发送中间消息。
    当启用流式输出时，通过定时编辑消息将新产生的 tokens 实时推送给用户。

    工作流程：
    1. Agent开始处理时调用 start_streaming()，检查渠道能力并启动定时刷新
    2. LLM 产生 token 时调用 emit() 积累到缓冲区
    3. 定时器周期性调用 _flush()：
       - 第一次有内容时发送新消息（通过 send_direct_message 获取 message_id）
       - 后续有新内容时编辑同一条消息（通过 edit_message）
    4. 工具调用时 take() 被调用：取走缓冲区内容（如果已流式发送则返回空），
       重置消息状态以便工具调用后的新内容开启新的流式消息
    5. Agent最终完成时调用 stop_streaming()：执行最后一次刷新，
       返回是否已通过流式发送完所有内容（调用方据此决定是否还需额外发送）
    """

    # 流式输出的刷新间隔（秒）
    FLUSH_INTERVAL = 1.0

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer = ""
        # 流式输出相关状态
        self._streaming_enabled = False
        self._flush_task: Optional[asyncio.Task] = None
        # 当前消息的发送信息（用于编辑消息）
        self._message_response: Optional[MessageResponse] = None
        # 已发送给用户的文本（用于追踪增量）
        self._sent_text = ""
        # 消息发送所需的上下文信息
        self._channel: Optional[str] = None
        self._source: Optional[str] = None
        self._user_id: Optional[str] = None
        self._username: Optional[str] = None
        self._title: str = "MoviePilot助手"

    def emit(self, token: str):
        """
        接收 LLM 流式 token，积累到缓冲区。
        """
        with self._lock:
            self._buffer += token

    async def take(self) -> str:
        """
        获取当前已积累的消息内容，获取后清空缓冲区。

        当流式输出启用时：
        1. 先暂停 flush loop（避免与后续发送产生竞争）
        2. 执行最终一次 flush（确保已有内容完整推送到流式消息）
        3. 如果内容已全部通过流式编辑发送给用户，返回空字符串（避免重复发送）
        4. 重置消息状态，以便工具执行后 LLM 产出的新内容开启新的流式消息
        5. 重新启动 flush loop（恢复后续流式输出能力）
        """
        if self._streaming_enabled:
            # 暂停 flush loop
            await self._cancel_flush_task()
            # 执行最终一次 flush，确保当前流式消息是完整的
            await self._flush()

        with self._lock:
            if not self._buffer:
                message = ""
                already_sent = False
            else:
                message = self._buffer
                logger.info(f"Agent消息: {message}")

                # 如果流式输出已经把内容发给用户了，工具不需要再发
                already_sent = (
                    self._streaming_enabled
                    and self._message_response is not None
                    and self._sent_text == self._buffer
                )

                self._buffer = ""

            # 重置流式消息状态，下次有新内容时会开启新消息
            self._sent_text = ""
            self._message_response = None

        # 恢复 flush loop（工具执行完成后 LLM 继续产出 token 时需要）
        if self._streaming_enabled:
            await self._restart_flush_loop()

        if already_sent or not message:
            return ""
        return message

    def clear(self):
        """
        清空缓冲区（不返回内容）
        """
        with self._lock:
            self._buffer = ""
            self._sent_text = ""
            self._message_response = None

    async def start_streaming(
        self,
        channel: Optional[str] = None,
        source: Optional[str] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        title: str = "MoviePilot助手",
    ):
        """
        启动流式输出。检查渠道是否支持消息编辑，如果支持则启动定时刷新任务。
        :param channel: 消息渠道
        :param source: 消息来源
        :param user_id: 用户ID
        :param username: 用户名
        :param title: 消息标题
        """
        self._channel = channel
        self._source = source
        self._user_id = user_id
        self._username = username
        self._title = title

        # 检查渠道是否支持消息编辑
        if not self._can_stream():
            logger.debug(f"渠道 {channel} 不支持消息编辑，不启用流式输出")
            return

        self._streaming_enabled = True
        self._sent_text = ""
        self._message_response = None

        # 启动异步定时刷新任务
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.debug("流式输出已启动")

    async def stop_streaming(self) -> bool:
        """
        停止流式输出。执行最后一次刷新确保所有内容都已发送。
        :return: 是否已经通过流式编辑将最终完整内容发送给了用户
                 （True 表示调用方无需再额外发送消息）
        """
        if not self._streaming_enabled:
            return False

        self._streaming_enabled = False

        # 取消定时任务
        await self._cancel_flush_task()

        # 执行最后一次刷新
        await self._flush()

        # 检查是否所有缓冲内容都已发送
        with self._lock:
            all_sent = (
                self._message_response is not None
                and self._sent_text
                and self._buffer == self._sent_text
            )
            # 重置状态
            self._sent_text = ""
            self._message_response = None
            if all_sent:
                # 所有内容已通过流式发送，清空缓冲区
                self._buffer = ""
            return all_sent

    def _can_stream(self) -> bool:
        """
        检查当前渠道是否支持流式输出（消息编辑）
        """
        if not self._channel:
            return False
        try:
            channel_enum = MessageChannel(self._channel)
            return ChannelCapabilityManager.supports_capability(
                channel_enum, ChannelCapability.MESSAGE_EDITING
            )
        except (ValueError, KeyError):
            return False

    async def _flush_loop(self):
        """
        定时刷新循环，定期将缓冲区内容发送/编辑到用户
        """
        try:
            while self._streaming_enabled:
                await asyncio.sleep(self.FLUSH_INTERVAL)
                if self._streaming_enabled:
                    await self._flush()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"流式刷新异常: {e}")

    async def _cancel_flush_task(self):
        """
        取消当前的定时刷新任务
        """
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

    async def _restart_flush_loop(self):
        """
        重新启动定时刷新任务（用于 take() 后恢复流式输出）
        """
        if not self._streaming_enabled:
            return
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def _flush(self):
        """
        将当前缓冲区内容刷新到用户消息
        - 如果还没有发送过消息，先发送一条新消息并记录message_id
        - 如果已经发送过消息，编辑该消息为最新的完整内容
        """
        with self._lock:
            current_text = self._buffer
            if not current_text or current_text == self._sent_text:
                # 没有新内容需要刷新
                return

        chain = _StreamChain()

        try:
            if self._message_response is None:
                # 第一次发送：发送新消息并获取 message_id
                response = chain.send_direct_message(
                    Notification(
                        channel=self._channel,
                        source=self._source,
                        userid=self._user_id,
                        username=self._username,
                        title=self._title,
                        text=current_text,
                    )
                )
                if response and response.success and response.message_id:
                    self._message_response = response
                    with self._lock:
                        self._sent_text = current_text
                    logger.debug(
                        f"流式输出初始消息已发送: message_id={response.message_id}"
                    )
                else:
                    logger.debug(
                        "流式输出初始消息发送失败或未返回message_id，降级为非流式输出"
                    )
                    self._streaming_enabled = False
            else:
                # 后续更新：编辑已有消息
                try:
                    channel_enum = MessageChannel(self._channel)
                except (ValueError, KeyError):
                    return

                success = chain.edit_message(
                    channel=channel_enum,
                    source=self._message_response.source,
                    message_id=self._message_response.message_id,
                    chat_id=self._message_response.chat_id,
                    text=current_text,
                    title=self._title,
                )
                if success:
                    with self._lock:
                        self._sent_text = current_text
                else:
                    logger.debug("流式输出消息编辑失败")
        except Exception as e:
            logger.error(f"流式输出刷新失败: {e}")

    @property
    def is_streaming(self) -> bool:
        """
        是否正在流式输出
        """
        return self._streaming_enabled

    @property
    def has_sent_message(self) -> bool:
        """
        是否已经通过流式输出发送过消息（当前轮次）
        """
        return self._message_response is not None
