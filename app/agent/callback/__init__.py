import asyncio
import threading
from typing import Optional, Tuple

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

    负责从 LLM 流式 token 中积累文本，并在支持消息编辑的渠道上实时推送给用户。

    工作流程：
    1. Agent开始处理时调用 start_streaming()，检查渠道能力并启动定时刷新
    2. LLM 产生 token 时调用 emit() 积累到缓冲区
    3. 定时器周期性调用 _flush()：
       - 第一次有内容时发送新消息（通过 send_direct_message 获取 message_id）
       - 后续有新内容时编辑同一条消息（通过 edit_message）
       - 当消息长度接近渠道限制时，冻结当前消息并发送新消息继续输出
    4. 工具调用时：
       - 流式渠道：工具消息直接 emit() 追加到 buffer，与 Agent 文字合并为同一条流式消息
       - 非流式渠道：调用 take() 取出已积累的文字，与工具消息合并独立发送
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
        # 当前消息的起始偏移量（buffer 中属于当前消息的起始位置）
        self._msg_start_offset = 0
        # 当前渠道的单条消息最大长度（0 表示不限制）
        self._max_message_length = 0
        # 消息发送所需的上下文信息
        self._channel: Optional[str] = None
        self._source: Optional[str] = None
        self._user_id: Optional[str] = None
        self._username: Optional[str] = None
        self._title: str = ""

    def emit(self, token: str):
        """
        接收 LLM 流式 token，积累到缓冲区。
        """
        with self._lock:
            # 如果存量消息结束是两个换行，则去掉新消息前面的换行，避免过多空行
            if self._buffer.endswith("\n\n") and token.startswith("\n"):
                token = token.lstrip("\n")
            self._buffer += token

    async def take(self) -> str:
        """
        获取当前已积累的消息内容，获取后清空缓冲区。

        用于非流式渠道：工具调用前取出 Agent 已产出的文字，
        与工具提示合并后独立发送。

        注意：流式渠道不调用此方法，工具消息直接 emit 到 buffer 中。
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
            self._sent_text = ""
            self._message_response = None
            self._msg_start_offset = 0

    async def start_streaming(
        self,
        channel: Optional[str] = None,
        source: Optional[str] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        title: str = "",
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
        self._msg_start_offset = 0

        # 从渠道能力中获取单条消息最大长度
        try:
            channel_enum = MessageChannel(self._channel)
            self._max_message_length = ChannelCapabilityManager.get_max_message_length(
                channel_enum
            )
        except (ValueError, KeyError):
            self._max_message_length = 0

        # 启动异步定时刷新任务
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.debug("流式输出已启动")

    async def stop_streaming(self) -> Tuple[bool, str]:
        """
        停止流式输出。执行最后一次刷新确保所有内容都已发送。
        :return: (all_sent, final_text)
                 all_sent: 是否已经通过流式编辑将最终完整内容发送给了用户
                           （True 表示调用方无需再额外发送消息）
                 final_text: 流式发送的完整文本内容（用于调用方保存消息记录）
        """
        if not self._streaming_enabled:
            return False, ""

        self._streaming_enabled = False

        # 取消定时任务
        await self._cancel_flush_task()

        # 执行最后一次刷新
        await self._flush()

        # 检查是否所有缓冲内容都已发送
        with self._lock:
            # 当前消息的文本 = buffer 中从 _msg_start_offset 开始的部分
            current_msg_text = self._buffer[self._msg_start_offset :]
            all_sent = (
                self._message_response is not None
                and self._sent_text
                and current_msg_text == self._sent_text
            )
            # 保留最终文本用于返回（返回完整 buffer 内容，包含所有分段消息）
            final_text = self._buffer if all_sent else ""
            # 重置状态
            self._sent_text = ""
            self._message_response = None
            self._msg_start_offset = 0
            if all_sent:
                # 所有内容已通过流式发送，清空缓冲区
                self._buffer = ""
            return all_sent, final_text

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

    async def _flush(self):
        """
        将当前缓冲区内容刷新到用户消息
        - 如果还没有发送过消息，先发送一条新消息并记录message_id
        - 如果已经发送过消息，编辑该消息为最新的完整内容
        - 如果当前消息内容超过长度限制，冻结当前消息并发送新消息继续输出
        """
        with self._lock:
            # 当前消息的文本 = buffer 中从 _msg_start_offset 开始的部分
            current_text = self._buffer[self._msg_start_offset :]
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
                # 检查当前消息内容是否超过长度限制
                if (
                    self._max_message_length
                    and len(current_text) > self._max_message_length
                ):
                    # 消息过长，冻结当前消息（保持最后一次成功编辑的内容）
                    # 将 offset 移动到已发送文本之后，开启新消息
                    logger.debug(
                        f"流式消息长度 {len(current_text)} 超过限制 {self._max_message_length}，启用新消息"
                    )
                    with self._lock:
                        self._msg_start_offset += len(self._sent_text)
                        current_text = self._buffer[self._msg_start_offset :]
                    self._message_response = None
                    self._sent_text = ""

                    # 如果偏移后还有新内容，立即发送为新消息
                    if current_text:
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
                                f"流式输出新消息已发送: message_id={response.message_id}"
                            )
                        else:
                            logger.debug("流式输出新消息发送失败，降级为非流式输出")
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
