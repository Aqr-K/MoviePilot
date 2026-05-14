"""发送语音消息工具。"""

import asyncio
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.llm.capability import AgentCapabilityManager
from app.agent.tools.base import MoviePilotTool, ToolChain
from app.core.config import settings
from app.log import logger
from app.schemas import Notification, NotificationType


class SendVoiceMessageInput(BaseModel):
    """发送语音消息工具输入。"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why a voice reply is the best fit in the current context",
    )
    message: str = Field(
        ...,
        description="The spoken content to send back to the user",
    )


class SendVoiceMessageTool(MoviePilotTool):
    name: str = "send_voice_message"
    sends_message: bool = True
    description: str = (
        "Send a voice reply to the current user. Use this only when the user explicitly asks for "
        "a voice reply or when spoken playback is clearly better than plain text. On channels "
        "without voice support or when TTS is unavailable, it automatically falls back to sending "
        "the same content as plain text."
    )
    args_schema: Type[BaseModel] = SendVoiceMessageInput
    require_admin: bool = False

    def get_tool_message(self, **kwargs) -> Optional[str]:
        message = kwargs.get("message") or ""
        if len(message) > 40:
            message = message[:40] + "..."
        return f"发送语音回复: {message}"

    async def run(self, message: str, **kwargs) -> str:
        if not message:
            return "语音回复内容不能为空"

        voice_path = None
        used_voice = False
        channel = self._channel or ""
        reply_mode = AgentCapabilityManager.resolve_reply_mode(
            channel=channel,
            source=self._source,
        )
        fallback_reason = "当前渠道不支持语音回复"
        if not AgentCapabilityManager.supports_audio_output():
            fallback_reason = "当前未启用音频输出"
        if (
            reply_mode == AgentCapabilityManager.REPLY_MODE_NATIVE
            and AgentCapabilityManager.is_audio_output_available()
        ):
            voice_file = await asyncio.to_thread(
                AgentCapabilityManager.synthesize_speech, message
            )
            if voice_file:
                voice_path = str(voice_file)
                used_voice = True
        elif reply_mode == AgentCapabilityManager.REPLY_MODE_NATIVE:
            fallback_reason = "当前未配置可用的语音合成能力"

        logger.info(
            "执行工具: %s, channel=%s, use_voice=%s, text_len=%s",
            self.name,
            channel,
            used_voice,
            len(message),
        )

        await ToolChain().async_post_message(
            Notification(
                channel=self._channel,
                source=self._source,
                mtype=NotificationType.Agent,
                userid=self._user_id,
                username=self._username,
                text=message,
                voice_path=voice_path,
                voice_caption=(
                    message
                    if voice_path and settings.AUDIO_OUTPUT_INCLUDE_TEXT
                    else None
                ),
            )
        )
        self._agent_context["user_reply_sent"] = True
        self._agent_context["reply_mode"] = "voice" if used_voice else "text_fallback"

        if used_voice:
            return "语音回复已发送"
        return f"{fallback_reason}，已自动回退为文字回复"
