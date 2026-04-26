import asyncio
import mimetypes
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional, Dict, Union, List
from urllib.parse import unquote, urlparse
import uuid

import base64

from app.agent import agent_manager
from app.chain import ChainBase
from app.chain.interaction import (
    MediaInteractionChain,
    agent_interaction_manager,
    media_interaction_manager,
)
from app.chain.skills import SkillsChain, skills_interaction_manager
from app.chain.transfer import TransferChain
from app.core.config import settings, global_vars
from app.helper.llm import LLMHelper
from app.helper.voice import VoiceHelper
from app.log import logger
from app.schemas import Notification, CommingMessage
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import EventType, MessageChannel
from app.utils.http import RequestUtils


class MessageChain(ChainBase):
    """
    外来消息处理链
    """

    # 用户会话信息 {userid: (session_id, last_time)}
    _user_sessions: Dict[Union[str, int], tuple] = {}
    # 会话超时时间（分钟）
    _session_timeout_minutes: int = 24 * 60

    def process(self, body: Any, form: Any, args: Any) -> None:
        """
        调用模块识别消息内容
        """
        # 消息来源
        source = args.get("source")
        # 获取消息内容
        info = self.message_parser(source=source, body=body, form=form, args=args)
        if not info:
            logger.info("消息链路未识别到有效消息: source=%s", source)
            return
        # 更新消息来源
        source = info.source
        # 渠道
        channel = info.channel
        # 用户ID
        userid = info.userid
        # 用户名（当渠道未提供公开用户名时，回退为 userid 的字符串，避免后续类型校验异常）
        username = (
            str(info.username) if info.username not in (None, "") else str(userid)
        )
        if userid is None or userid == "":
            logger.debug(f"未识别到用户ID：{body}{form}{args}")
            return

        # 消息内容
        text = str(info.text).strip() if info.text else ""
        images = info.images
        audio_refs = info.audio_refs
        files = info.files
        if not text and not images and not audio_refs and not files:
            logger.debug(f"未识别到消息内容：：{body}{form}{args}")
            return

        # 获取原消息ID信息
        original_message_id = info.message_id
        original_chat_id = info.chat_id

        # 处理消息
        self.handle_message(
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            text=text,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
            images=images,
            audio_refs=audio_refs,
            files=files,
        )

    def handle_message(
        self,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        text: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
        images: Optional[List[CommingMessage.MessageImage]] = None,
        audio_refs: Optional[List[str]] = None,
        files: Optional[List[CommingMessage.MessageAttachment]] = None,
    ) -> None:
        """
        识别消息内容，执行操作
        """
        images = CommingMessage.MessageImage.normalize_list(images)

        # 识别语音为文本
        reply_with_voice = bool(audio_refs)
        if audio_refs:
            transcript = self._transcribe_audio_refs(audio_refs, channel, source)
            merged_parts = []
            seen_parts = set()
            for item in [text.strip() if text else "", transcript or ""]:
                normalized = item.strip()
                if not normalized or normalized in seen_parts:
                    continue
                seen_parts.add(normalized)
                merged_parts.append(normalized)
            text = "\n".join(merged_parts).strip()
            if not text:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="语音识别失败，请稍后重试",
                    )
                )
                return

        if not text.startswith("CALLBACK:"):
            self._record_user_message(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                text=text,
            )

        if text.startswith("CALLBACK:"):
            if ChannelCapabilityManager.supports_callbacks(channel):
                self._handle_callback(
                    text=text,
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    original_message_id=original_message_id,
                    original_chat_id=original_chat_id,
                )
            else:
                logger.warning(
                    "渠道 %s 不支持回调，但收到了回调消息：%s",
                    channel.value,
                    text,
                )
            return

        if text.startswith("/") and not text.lower().startswith("/ai"):
            self.eventmanager.send_event(
                EventType.CommandExcute,
                {"cmd": text, "user": userid, "channel": channel, "source": source},
            )
            return

        if skills_interaction_manager.get_by_user(userid):
            if SkillsChain().handle_text_interaction(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                text=text,
            ):
                return

        if media_interaction_manager.get_by_user(userid):
            if MediaInteractionChain().handle_text_interaction(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                text=text,
            ):
                return

        if text.lower().startswith("/ai"):
            self._handle_ai_message(
                text=text,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                images=images,
                files=files,
                reply_with_voice=reply_with_voice,
            )
            return

        if settings.AI_AGENT_ENABLE and (settings.AI_AGENT_GLOBAL or images or files):
            self._handle_ai_message(
                text=text,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                images=images,
                files=files,
                reply_with_voice=reply_with_voice,
            )
            return

        if MediaInteractionChain().handle_text_interaction(
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            text=text,
        ):
            return

        self.eventmanager.send_event(
            EventType.UserMessage,
            {
                "text": text,
                "userid": userid,
                "channel": channel,
                "source": source,
            },
        )

    def _handle_callback(
        self,
        text: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        处理按钮回调
        """

        # 提取回调数据
        callback_data = text[9:]  # 去掉 "CALLBACK:" 前缀
        logger.info(f"处理按钮回调：{callback_data}")

        if self._handle_transfer_callback(
            callback_data=callback_data,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
        ):
            return

        if SkillsChain().handle_callback_interaction(
            callback_data=callback_data,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        ):
            return

        if MediaInteractionChain().handle_callback_interaction(
            callback_data=callback_data,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        ):
            return

        if self._handle_agent_choice_callback(
            callback_data=callback_data,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        ):
            return

        # 插件消息的事件回调 [PLUGIN]插件ID|内容
        if callback_data.startswith("[PLUGIN]"):
            # 提取插件ID和内容
            plugin_id, content = callback_data.split("|", 1)
            # 广播给插件处理
            self.eventmanager.send_event(
                EventType.MessageAction,
                {
                    "plugin_id": plugin_id.replace("[PLUGIN]", ""),
                    "text": content,
                    "userid": userid,
                    "channel": channel,
                    "source": source,
                    "original_message_id": original_message_id,
                    "original_chat_id": original_chat_id,
                },
            )
            return

        logger.error(f"回调数据格式错误：{callback_data}")
        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title="回调数据格式错误，请检查！",
            )
        )

    @staticmethod
    def _parse_transfer_callback(
        callback_data: str,
    ) -> Optional[tuple[str, int]]:
        """
        解析整理失败通知按钮回调。
        """
        for prefix, action in (
            ("transfer_retry_", "retry"),
            ("transfer_ai_retry_", "ai_retry"),
        ):
            if callback_data.startswith(prefix):
                history_id = callback_data.replace(prefix, "", 1)
                if history_id.isdigit():
                    return action, int(history_id)
        return None

    def _handle_transfer_callback(
        self,
        callback_data: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> bool:
        """
        处理整理失败通知中的重试类按钮。
        """
        callback = self._parse_transfer_callback(callback_data)
        if not callback:
            return False

        action, history_id = callback
        if action == "retry":
            self._retry_transfer_history(
                history_id=history_id,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
        else:
            self._take_over_transfer_history_by_ai(
                history_id=history_id,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
        return True

    @staticmethod
    def _parse_agent_choice_callback(
        callback_data: str,
    ) -> Optional[tuple[str, int]]:
        """
        解析 Agent 按钮选择回调。
        """
        if callback_data.startswith("agent_interaction:choice:"):
            try:
                _, _, request_id, option_index = callback_data.split(":", 3)
            except ValueError:
                return None
        elif callback_data.startswith("agent_choice:"):
            # 兼容旧格式，避免已发送的按钮失效
            try:
                _, request_id, option_index = callback_data.split(":", 2)
            except ValueError:
                return None
        else:
            return None
        if not request_id or not option_index.isdigit():
            return None
        return request_id, int(option_index)

    def _handle_agent_choice_callback(
        self,
        callback_data: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> bool:
        """
        将 Agent 按钮选择回传为同一会话中的下一条用户消息。
        """
        callback = self._parse_agent_choice_callback(callback_data)
        if not callback:
            return False

        request_id, option_index = callback
        resolved = agent_interaction_manager.resolve(
            request_id=request_id,
            option_index=option_index,
            user_id=str(userid),
        )
        if not resolved:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="该选择已失效，请重新发起选择",
                )
            )
            return True

        request, option = resolved
        selected_text = option.value
        self._update_interaction_message_feedback(
            channel=channel,
            source=source,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
            title=request.title,
            prompt=request.prompt,
            selected_label=option.label,
        )
        self._bind_session_id(userid, request.session_id)
        self._record_user_message(
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            text=selected_text,
        )
        self._handle_ai_message(
            text=selected_text,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
            session_id=request.session_id,
        )
        return True

    def _update_interaction_message_feedback(
        self,
        channel: MessageChannel,
        source: str,
        original_message_id: Optional[Union[str, int]],
        original_chat_id: Optional[str],
        prompt: str,
        selected_label: str,
        title: Optional[str] = None,
    ) -> None:
        """
        在用户点击交互按钮后，立即更新原消息，明确显示已选择的内容。
        """
        if not original_message_id or not original_chat_id:
            return

        lines = [prompt.strip()]
        if selected_label:
            lines.append(f"已选择：{selected_label}")
        feedback_text = "\n\n".join(line for line in lines if line)
        self.edit_message(
            channel=channel,
            source=source,
            message_id=original_message_id,
            chat_id=original_chat_id,
            title=title,
            text=feedback_text,
        )

    def _retry_transfer_history(
        self,
        history_id: int,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> None:
        """
        立即重新整理一条失败的整理记录。
        """
        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=f"开始重新整理记录 #{history_id} ...",
            )
        )

        state, errmsg = TransferChain().redo_transfer_history(history_id)
        if state:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=f"整理记录 #{history_id} 已重新整理",
                    link=settings.MP_DOMAIN("#/history"),
                )
            )
            return

        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title="重新整理失败",
                text=errmsg,
                link=settings.MP_DOMAIN("#/history"),
            )
        )

    def _take_over_transfer_history_by_ai(
        self,
        history_id: int,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> None:
        """
        由智能助手接管一条失败的整理记录。
        """
        if not settings.AI_AGENT_ENABLE:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="MoviePilot智能助手未启用，请在系统设置中启用",
                )
            )
            return

        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=f"已将整理记录 #{history_id} 交给智能助手处理",
                text="处理完成后会在这里回复结果。",
                link=settings.MP_DOMAIN("#/history"),
            )
        )

        async def _run_ai_takeover():
            final_output = ""

            def _capture_output(text_output: str):
                nonlocal final_output
                final_output = text_output or ""

            try:
                await agent_manager.manual_redo_transfer(
                    history_id=history_id,
                    output_callback=_capture_output,
                )
                await self.async_post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="智能助手整理完成",
                        text=final_output.strip()
                        or f"整理记录 #{history_id} 已由智能助手处理完成。",
                        link=settings.MP_DOMAIN("#/history"),
                    )
                )
            except Exception as e:
                await self.async_post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="智能助手整理失败",
                        text=str(e),
                        link=settings.MP_DOMAIN("#/history"),
                    )
                )

        asyncio.run_coroutine_threadsafe(_run_ai_takeover(), global_vars.loop)

    def _get_or_create_session_id(self, userid: Union[str, int]) -> str:
        """
        获取或创建会话ID
        如果用户上次会话在15分钟内，则复用相同的会话ID；否则创建新的会话ID
        """
        current_time = datetime.now()

        # 检查用户是否有已存在的会话
        if userid in self._user_sessions:
            session_id, last_time = self._user_sessions[userid]

            # 计算时间差
            time_diff = current_time - last_time

            # 如果时间差小于等于xx分钟，复用会话ID
            if time_diff <= timedelta(minutes=self._session_timeout_minutes):
                # 更新最后使用时间
                self._user_sessions[userid] = (session_id, current_time)
                logger.info(
                    f"复用会话ID: {session_id}, 用户: {userid}, 距离上次会话: {time_diff.total_seconds() / 60:.1f}分钟"
                )
                return session_id

        # 创建新的会话ID
        new_session_id = f"user_{userid}_{int(time.time())}"
        self._user_sessions[userid] = (new_session_id, current_time)
        logger.info(f"创建新会话ID: {new_session_id}, 用户: {userid}")
        return new_session_id

    def _bind_session_id(self, userid: Union[str, int], session_id: str) -> None:
        """
        将用户会话绑定到指定的 session_id，并刷新最后活动时间。
        """
        self._user_sessions[userid] = (session_id, datetime.now())

    def _record_user_message(
        self,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        text: str,
    ) -> None:
        """
        保存一条用户消息到消息历史与数据库。
        """
        self.messagehelper.put(
            CommingMessage(
                userid=userid,
                username=username,
                channel=channel,
                source=source,
                text=text,
            ),
            role="user",
        )
        self.messageoper.add(
            channel=channel,
            source=source,
            userid=username or userid,
            text=text,
            action=0,
        )

    def clear_user_session(self, userid: Union[str, int]) -> bool:
        """
        清除指定用户的会话信息
        返回是否成功清除
        """
        if userid in self._user_sessions:
            session_id, _ = self._user_sessions.pop(userid)
            logger.info(f"已清除用户 {userid} 的会话: {session_id}")
            return True
        return False

    def remote_clear_session(
        self,
        channel: MessageChannel,
        userid: Union[str, int],
        source: Optional[str] = None,
    ):
        """
        清除用户会话（远程命令接口）
        """
        # 获取并清除会话信息
        session_id = None
        if userid in self._user_sessions:
            session_id, _ = self._user_sessions.pop(userid)
            logger.info(f"已清除用户 {userid} 的会话: {session_id}")

        # 如果有会话ID，同时清除智能体的会话记忆
        if session_id:
            try:
                asyncio.run_coroutine_threadsafe(
                    agent_manager.clear_session(
                        session_id=session_id, user_id=str(userid)
                    ),
                    global_vars.loop,
                )
            except Exception as e:
                logger.warning(f"清除智能体会话记忆失败: {e}")

            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    title="智能体会话已清除，下次将创建新的会话",
                    userid=userid,
                )
            )
        else:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    title="您当前没有活跃的智能体会话",
                    userid=userid,
                )
            )

    def remote_stop_agent(
        self,
        channel: MessageChannel,
        userid: Union[str, int],
        source: Optional[str] = None,
    ):
        """
        应急停止当前正在执行的Agent推理（远程命令接口）。
        与 /clear_session 不同，此命令不会清除会话和记忆，
        停止后用户仍可继续对话。
        """
        # 查找用户的会话ID（不弹出，保留会话）
        session_info = self._user_sessions.get(userid)
        if session_info:
            session_id, _ = session_info
            try:
                future = asyncio.run_coroutine_threadsafe(
                    agent_manager.stop_current_task(session_id=session_id),
                    global_vars.loop,
                )
                stopped = future.result(timeout=10)
            except Exception as e:
                logger.warning(f"停止Agent推理失败: {e}")
                stopped = False

            if stopped:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        title="智能体推理已应急停止，会话记忆已保留，您可以继续对话",
                        userid=userid,
                    )
                )
            else:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        title="当前没有正在执行的智能体任务",
                        userid=userid,
                    )
                )
        else:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    title="您当前没有活跃的智能体会话",
                    userid=userid,
                )
            )

    @staticmethod
    def _format_token_count(value: Optional[int]) -> str:
        return f"{value:,}" if value is not None else "未知"

    @classmethod
    def _format_session_status_text(cls, status: Dict[str, Any]) -> str:
        context_window_tokens = status.get("context_window_tokens")
        last_input_tokens = status.get("last_input_tokens")
        if context_window_tokens and status.get("model_call_count"):
            context_ratio = status.get("last_context_usage_ratio")
            if context_ratio is None and last_input_tokens is not None:
                context_ratio = last_input_tokens / context_window_tokens
            context_usage_text = (
                f"{cls._format_token_count(last_input_tokens)} / "
                f"{cls._format_token_count(context_window_tokens)} "
                f"({context_ratio * 100:.2f}%)"
                if context_ratio is not None
                else f"{cls._format_token_count(last_input_tokens)} / "
                f"{cls._format_token_count(context_window_tokens)}"
            )
        else:
            context_usage_text = "暂无模型调用数据"

        lines = [
            f"会话ID: {status.get('session_id') or '未知'}",
            f"执行状态: {'运行中' if status.get('is_processing') else '空闲'}",
            f"当前模型: {status.get('model') or '未知'}",
            f"上下文窗口: {cls._format_token_count(context_window_tokens)} tokens",
            f"最近一次上下文占用: {context_usage_text}",
            f"最近一次 tokens: 输入 {cls._format_token_count(status.get('last_input_tokens'))} / 输出 {cls._format_token_count(status.get('last_output_tokens'))} / 总计 {cls._format_token_count(status.get('last_total_tokens'))}",
            f"当前会话累计 tokens: 输入 {cls._format_token_count(status.get('total_input_tokens'))} / 输出 {cls._format_token_count(status.get('total_output_tokens'))} / 总计 {cls._format_token_count(status.get('total_tokens'))}",
            f"模型调用次数: {status.get('model_call_count', 0)}",
            f"排队消息数: {status.get('pending_messages', 0)}",
            f"最后更新: {status.get('last_updated_at') or '暂无'}",
        ]
        return "\n".join(lines)

    def remote_session_status(
        self,
        channel: MessageChannel,
        userid: Union[str, int],
        source: Optional[str] = None,
    ):
        """查询当前用户的智能体会话状态。"""
        session_info = self._user_sessions.get(userid)
        if not session_info:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    title="您当前没有活跃的智能体会话",
                    userid=userid,
                )
            )
            return

        session_id, _ = session_info
        status = agent_manager.get_session_status(session_id=session_id)
        self.post_message(
            Notification(
                channel=channel,
                source=source,
                title="当前智能体会话状态",
                text=self._format_session_status_text(status),
                userid=userid,
            )
        )

    def _handle_ai_message(
        self,
        text: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        images: Optional[List[CommingMessage.MessageImage]] = None,
        files: Optional[List[CommingMessage.MessageAttachment]] = None,
        reply_with_voice: bool = False,
        session_id: Optional[str] = None,
    ) -> None:
        """
        处理AI智能体消息
        """
        try:
            # 检查AI智能体是否启用
            if not settings.AI_AGENT_ENABLE:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="MoviePilot智能助手未启用，请在系统设置中启用",
                    )
                )
                return

            images = CommingMessage.MessageImage.normalize_list(images)

            # 提取用户消息
            if text.lower().startswith("/ai"):
                user_message = text[3:].strip()  # 移除 "/ai" 前缀（大小写不敏感）
            else:
                user_message = text.strip()  # 按原消息处理

            if not user_message and not images and not files:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="请输入您的问题或需求",
                    )
                )
                return

            # 生成或复用会话ID
            session_id = session_id or self._get_or_create_session_id(userid)
            self._bind_session_id(userid, session_id)

            # 下载图片并转为base64
            original_images = images
            all_files = list(files or [])
            if images and LLMHelper.supports_image_input():
                images = self._download_images_to_base64(images, channel, source)
                if original_images and not images and not user_message and not files:
                    self.post_message(
                        Notification(
                            channel=channel,
                            source=source,
                            userid=userid,
                            username=username,
                            title="图片读取失败，请稍后重试",
                        )
                    )
                    return
            elif images:
                image_attachments = self._build_image_attachments(images)
                if (
                    original_images
                    and not image_attachments
                    and not user_message
                    and not files
                ):
                    self.post_message(
                        Notification(
                            channel=channel,
                            source=source,
                            userid=userid,
                            username=username,
                            title="图片读取失败，请稍后重试",
                        )
                    )
                    return
                all_files.extend(image_attachments)
                images = None

            prepared_files = self._prepare_agent_files(
                session_id=session_id,
                files=all_files,
                channel=channel,
                source=source,
            )
            if all_files and not prepared_files and not user_message and not images:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title="文件读取失败，请稍后重试",
                    )
                )
                return

            # 在事件循环中处理
            asyncio.run_coroutine_threadsafe(
                agent_manager.process_message(
                    session_id=session_id,
                    user_id=str(userid),
                    message=user_message,
                    images=images,
                    files=prepared_files,
                    channel=channel.value if channel else None,
                    source=source,
                    username=username,
                    reply_with_voice=reply_with_voice,
                ),
                global_vars.loop,
            )

        except Exception as e:
            logger.error(f"处理AI智能体消息失败: {e}")
            self.messagehelper.put(
                f"AI智能体处理失败: {str(e)}", role="system", title="MoviePilot助手"
            )

    def _transcribe_audio_refs(
        self, audio_refs: List[str], channel: MessageChannel, source: str
    ) -> Optional[str]:
        """
        下载并识别语音消息，仅处理当前已接入的渠道。
        """
        if not audio_refs:
            return None
        if not VoiceHelper.is_available("stt"):
            logger.warning("语音能力未配置，跳过语音识别")
            return None

        transcripts = []
        for audio_ref in audio_refs:
            try:
                if audio_ref.startswith("tg://voice_file_id/"):
                    file_id = audio_ref.replace("tg://voice_file_id/", "", 1)
                    content = self.run_module(
                        "download_telegram_file_bytes", file_id=file_id, source=source
                    )
                    filename = "input.ogg"
                elif audio_ref.startswith("tg://audio_file_id/"):
                    file_id = audio_ref.replace("tg://audio_file_id/", "", 1)
                    content = self.run_module(
                        "download_telegram_file_bytes", file_id=file_id, source=source
                    )
                    filename = "input.mp3"
                elif audio_ref.startswith("wxwork://voice_media_id/"):
                    content = self.run_module(
                        "download_wechat_media_bytes",
                        media_ref=audio_ref,
                        source=source,
                    )
                    filename = "input.amr"
                elif audio_ref.startswith("slack://file/"):
                    content = self.run_module(
                        "download_slack_file_bytes", file_ref=audio_ref, source=source
                    )
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                elif audio_ref.startswith("discord://file/"):
                    content = self.run_module(
                        "download_discord_file_bytes", file_ref=audio_ref, source=source
                    )
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                elif audio_ref.startswith("qq://file/"):
                    content = self.run_module(
                        "download_qq_file_bytes", file_ref=audio_ref, source=source
                    )
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                elif audio_ref.startswith("vocechat://file/"):
                    content = self.run_module(
                        "download_vocechat_file_bytes",
                        file_ref=audio_ref,
                        source=source,
                    )
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                elif audio_ref.startswith("synology://file/"):
                    content = self.run_module(
                        "download_synologychat_file_bytes",
                        file_ref=audio_ref,
                        source=source,
                    )
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                elif audio_ref.startswith("wxbot://voice"):
                    continue
                elif audio_ref.startswith("http"):
                    resp = RequestUtils(timeout=30).get_res(audio_ref)
                    content = resp.content if resp and resp.content else None
                    filename = self._guess_audio_filename(
                        audio_ref, default="input.ogg"
                    )
                else:
                    logger.debug(
                        "暂不支持的语音引用: channel=%s, source=%s, ref=%s",
                        channel.value if channel else None,
                        source,
                        audio_ref,
                    )
                    continue

                if not content:
                    logger.warning(
                        "语音下载失败，跳过识别: channel=%s, source=%s, ref=%s",
                        channel.value if channel else None,
                        source,
                        audio_ref,
                    )
                    continue

                transcript = VoiceHelper.transcribe_bytes(
                    content=content, filename=filename
                )
                if transcript:
                    transcripts.append(transcript)
                    logger.info(
                        "语音识别成功: channel=%s, source=%s, ref=%s, text_len=%s",
                        channel.value if channel else None,
                        source,
                        audio_ref,
                        len(transcript),
                    )
            except Exception as err:
                logger.error(f"语音识别失败: {err}")

        return "\n".join(transcripts).strip() if transcripts else None

    @staticmethod
    def _guess_audio_filename(audio_ref: str, default: str = "input.ogg") -> str:
        """
        根据引用中的扩展名推测音频文件名，便于 STT 服务识别格式。
        """
        if not audio_ref:
            return default
        raw_ref = unquote(audio_ref).split("?", 1)[0].split("#", 1)[0]
        match = re.search(
            r"([^/]+\.(mp3|m4a|wav|ogg|oga|opus|aac|amr|flac|mpga|mpeg|webm))$",
            raw_ref,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1)
        return default

    def _download_images_to_base64(
        self,
        images: List[CommingMessage.MessageImage],
        channel: MessageChannel,
        source: str,
    ) -> List[str]:
        """
        下载图片并转为base64
        """
        images = CommingMessage.MessageImage.normalize_list(images)
        if not images:
            return None
        base64_images = []
        for image in images:
            img = image.ref
            try:
                if img.startswith("data:"):
                    base64_images.append(img)
                elif img.startswith("tg://file_id/"):
                    file_id = img.replace("tg://file_id/", "")
                    base64_data = self.run_module(
                        "download_telegram_file_to_base64",
                        file_id=file_id,
                        source=source,
                    )
                    if base64_data:
                        base64_images.append(f"data:image/jpeg;base64,{base64_data}")
                        logger.info(
                            "图片下载成功: channel=%s, source=%s, input=%s, output=data:image/jpeg;base64...(omitted)",
                            channel.value if channel else None,
                            source,
                            img,
                        )
                elif img.startswith("wxwork://media_id/") or img.startswith(
                    "wxbot://image/"
                ):
                    data_url = self.run_module(
                        "download_wechat_image_to_data_url",
                        image_ref=img,
                        source=source,
                    )
                    if data_url:
                        base64_images.append(data_url)
                elif channel == MessageChannel.Slack:
                    data_url = self.run_module(
                        "download_slack_file_to_data_url", file_url=img, source=source
                    )
                    if data_url:
                        base64_images.append(data_url)
                elif img.startswith("vocechat://file/"):
                    data_url = self.run_module(
                        "download_vocechat_image_to_data_url",
                        image_ref=img,
                        source=source,
                    )
                    if data_url:
                        base64_images.append(data_url)
                elif img.startswith("http"):
                    resp = RequestUtils(timeout=30).get_res(img)
                    if resp and resp.content:
                        base64_data = base64.b64encode(resp.content).decode()
                        mime_type = resp.headers.get("Content-Type", "image/jpeg")
                        base64_images.append(f"data:{mime_type};base64,{base64_data}")
            except Exception as e:
                logger.error(f"下载图片失败: {img}, error: {e}")
        return base64_images if base64_images else None

    def _build_image_attachments(
        self, images: List[CommingMessage.MessageImage]
    ) -> List[CommingMessage.MessageAttachment]:
        """
        将图片引用转换为附件描述，以便按文件方式交给 Agent 处理。
        """
        images = CommingMessage.MessageImage.normalize_list(images)
        if not images:
            return []

        attachments = []
        for index, image in enumerate(images, start=1):
            image_ref = image.ref
            if not image_ref:
                continue
            name = image.name or self._guess_image_attachment_name(image_ref, index)
            mime_type = image.mime_type or self._guess_image_mime_type(image_ref, name)
            attachments.append(
                CommingMessage.MessageAttachment(
                    ref=image_ref,
                    name=name,
                    mime_type=mime_type,
                    size=image.size,
                )
            )
        return attachments

    def _prepare_agent_files(
        self,
        session_id: str,
        files: Optional[List[CommingMessage.MessageAttachment]],
        channel: MessageChannel,
        source: str,
    ) -> Optional[List[dict]]:
        """
        下载用户上传的文件，落盘到临时目录，并生成文本镜像供 Agent 使用。
        """
        if not files:
            return None

        prepared_files = []
        for attachment in files:
            payload = {
                "name": attachment.name,
                "mime_type": attachment.mime_type,
                "size": attachment.size,
                "ref": attachment.ref,
                "status": "download_failed",
            }
            try:
                content = self._download_message_file_bytes(
                    file_ref=attachment.ref,
                    channel=channel,
                    source=source,
                )
                if not content:
                    prepared_files.append(payload)
                    continue

                local_path = self._save_agent_attachment(
                    session_id=session_id,
                    filename=attachment.name,
                    content=content,
                    mime_type=attachment.mime_type,
                )
                payload.update(
                    {
                        "local_path": str(local_path),
                        "status": "ready",
                    }
                )
            except Exception as err:
                logger.error(f"准备文件上下文失败: {attachment.ref}, error: {err}")
                payload["error"] = str(err)
            prepared_files.append(payload)

        return prepared_files or None

    def _download_message_file_bytes(
        self, file_ref: str, channel: MessageChannel, source: str
    ) -> Optional[bytes]:
        """
        下载消息附件的原始字节。
        """
        if not file_ref:
            return None
        if file_ref.startswith("data:"):
            return self._decode_data_url_bytes(file_ref)
        if file_ref.startswith("tg://file_id/"):
            file_id = file_ref.replace("tg://file_id/", "", 1)
            return self.run_module(
                "download_telegram_file_bytes", file_id=file_id, source=source
            )
        if file_ref.startswith("tg://document_file_id/"):
            file_id = file_ref.replace("tg://document_file_id/", "", 1)
            return self.run_module(
                "download_telegram_file_bytes", file_id=file_id, source=source
            )
        if file_ref.startswith("wxwork://media_id/"):
            return self.run_module(
                "download_wechat_media_bytes", media_ref=file_ref, source=source
            )
        if file_ref.startswith("wxwork://file_media_id/"):
            return self.run_module(
                "download_wechat_media_bytes", media_ref=file_ref, source=source
            )
        if file_ref.startswith("wxbot://image/"):
            data_url = self.run_module(
                "download_wechat_image_to_data_url", image_ref=file_ref, source=source
            )
            return self._decode_data_url_bytes(data_url) if data_url else None
        if file_ref.startswith("wxbot://file/"):
            file_url = unquote(file_ref.replace("wxbot://file/", "", 1))
            resp = RequestUtils(timeout=30).get_res(file_url)
            return resp.content if resp and resp.content else None
        if file_ref.startswith("slack://file/"):
            return self.run_module(
                "download_slack_file_bytes", file_ref=file_ref, source=source
            )
        if file_ref.startswith("discord://file/"):
            return self.run_module(
                "download_discord_file_bytes", file_ref=file_ref, source=source
            )
        if file_ref.startswith("qq://file/"):
            return self.run_module(
                "download_qq_file_bytes", file_ref=file_ref, source=source
            )
        if file_ref.startswith("vocechat://file/"):
            return self.run_module(
                "download_vocechat_file_bytes", file_ref=file_ref, source=source
            )
        if file_ref.startswith("synology://file/"):
            return self.run_module(
                "download_synologychat_file_bytes", file_ref=file_ref, source=source
            )
        if file_ref.startswith("http"):
            if channel == MessageChannel.Slack:
                data_url = self.run_module(
                    "download_slack_file_to_data_url", file_url=file_ref, source=source
                )
                return self._decode_data_url_bytes(data_url) if data_url else None
            resp = RequestUtils(timeout=30).get_res(file_ref)
            return resp.content if resp and resp.content else None
        logger.debug(
            "暂不支持的文件引用: channel=%s, source=%s, ref=%s",
            channel.value if channel else None,
            source,
            file_ref,
        )
        return None

    def _save_agent_attachment(
        self,
        session_id: str,
        filename: Optional[str],
        content: bytes,
        mime_type: Optional[str] = None,
    ) -> Path:
        """
        将用户上传文件写入临时目录，并返回本地路径。
        """
        safe_name = self._sanitize_attachment_name(filename, mime_type)
        base_dir = settings.TEMP_PATH / "agent_uploads" / session_id
        base_dir.mkdir(parents=True, exist_ok=True)

        file_id = uuid.uuid4().hex[:8]
        local_path = base_dir / f"{file_id}_{safe_name}"
        local_path.write_bytes(content or b"")
        return local_path

    @staticmethod
    def _sanitize_attachment_name(
        filename: Optional[str], mime_type: Optional[str] = None
    ) -> str:
        """
        规范化附件文件名，避免路径穿越和非法字符。
        """
        name = Path(filename or "attachment").name
        name = re.sub(r"[^\w.\-]+", "_", name, flags=re.ASCII).strip("._")
        if not name:
            name = "attachment"
        if "." not in name:
            mime = (mime_type or "").split(";", 1)[0].strip().lower()
            default_ext = {
                "image/jpeg": ".jpg",
                "image/png": ".png",
                "image/gif": ".gif",
                "image/webp": ".webp",
                "image/bmp": ".bmp",
                "application/json": ".json",
                "text/plain": ".txt",
                "text/markdown": ".md",
                "text/csv": ".csv",
            }.get(mime)
            if default_ext:
                name = f"{name}{default_ext}"
        return name

    @staticmethod
    def _guess_image_attachment_name(image_ref: str, index: int) -> str:
        """
        根据图片引用推测附件名。
        """
        if not image_ref:
            return f"image_{index}.jpg"
        if image_ref.startswith("data:"):
            mime_part = image_ref[5:].split(";", 1)[0].strip().lower()
            ext = mimetypes.guess_extension(mime_part) or ".jpg"
            return f"image_{index}{ext}"

        parsed = urlparse(unquote(image_ref))
        name = Path(parsed.path).name if parsed.path else ""
        if name and "." in name:
            return name
        return f"image_{index}.jpg"

    @staticmethod
    def _guess_image_mime_type(image_ref: str, filename: Optional[str]) -> str:
        """
        根据图片引用或文件名推测 MIME 类型。
        """
        if image_ref and image_ref.startswith("data:"):
            mime = image_ref[5:].split(";", 1)[0].strip().lower()
            return mime or "image/jpeg"
        guessed, _ = mimetypes.guess_type(filename or "")
        if guessed and guessed.startswith("image/"):
            return guessed
        return "image/jpeg"

    @staticmethod
    def _decode_data_url_bytes(data_url: Optional[str]) -> Optional[bytes]:
        """
        将 data URL 解码为原始字节。
        """
        if not data_url or not data_url.startswith("data:"):
            return None
        try:
            _, payload = data_url.split(",", 1)
        except ValueError:
            return None
        try:
            return base64.b64decode(payload)
        except Exception:
            return None
