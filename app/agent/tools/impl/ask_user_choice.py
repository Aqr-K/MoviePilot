"""让用户通过按钮进行选择的工具。"""

from typing import List, Optional, Type

from pydantic import BaseModel, Field, model_validator

from app.agent.tools.base import MoviePilotTool, ToolChain
from app.chain.interaction import (
    AgentInteractionOption,
    agent_interaction_manager,
)
from app.log import logger
from app.schemas import Notification, NotificationType
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import MessageChannel


class UserChoiceOptionInput(BaseModel):
    """单个按钮选项。"""

    label: str = Field(..., description="Text shown on the button")
    value: str = Field(
        ...,
        description="The exact content that will be sent back to the agent after the user clicks this button",
    )

    @model_validator(mode="after")
    def validate_option(self):
        if not self.label.strip():
            raise ValueError("label 不能为空")
        if not self.value.strip():
            raise ValueError("value 不能为空")
        return self


class AskUserChoiceInput(BaseModel):
    """按钮选择工具输入。"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why the agent needs the user to choose from buttons",
    )
    message: str = Field(
        ...,
        description="Question or prompt shown to the user together with the buttons",
    )
    title: Optional[str] = Field(
        None,
        description="Optional short title displayed above the question",
    )
    options: List[UserChoiceOptionInput] = Field(
        ...,
        description="Button options to show to the user",
    )

    @model_validator(mode="after")
    def validate_payload(self):
        if not self.message.strip():
            raise ValueError("message 不能为空")
        if not self.options:
            raise ValueError("options 至少需要提供一个")
        return self


class AskUserChoiceTool(MoviePilotTool):
    name: str = "ask_user_choice"
    description: str = (
        "Ask the user to choose from button options on channels that support interactive buttons. "
        "After the user clicks a button, the selected value will come back as the user's next message."
    )
    args_schema: Type[BaseModel] = AskUserChoiceInput
    require_admin: bool = False

    def get_tool_message(self, **kwargs) -> Optional[str]:
        message = kwargs.get("message", "") or ""
        if len(message) > 40:
            message = message[:40] + "..."
        return f"正在发送按钮选择: {message}"

    @staticmethod
    def _truncate_button_text(text: str, max_length: int) -> str:
        if max_length <= 0 or len(text) <= max_length:
            return text
        if max_length <= 3:
            return text[:max_length]
        return text[: max_length - 3] + "..."

    async def run(
        self,
        message: str,
        options: List[UserChoiceOptionInput],
        title: Optional[str] = None,
        **kwargs,
    ) -> str:
        if not self._channel or not self._source:
            return "当前不在可回传消息的会话中，无法发起按钮选择"

        try:
            channel = MessageChannel(self._channel)
        except ValueError:
            return f"不支持的消息渠道: {self._channel}"

        if not (
            ChannelCapabilityManager.supports_buttons(channel)
            and ChannelCapabilityManager.supports_callbacks(channel)
        ):
            return f"当前渠道 {channel.value} 不支持按钮选择"

        max_per_row = 1
        max_rows = ChannelCapabilityManager.get_max_button_rows(channel)
        max_text_length = ChannelCapabilityManager.get_max_button_text_length(channel)
        max_options = max_per_row * max_rows
        if len(options) > max_options:
            return f"当前渠道最多支持 {max_options} 个按钮选项"

        choice_options = [
            AgentInteractionOption(
                label=option.label.strip(), value=option.value.strip()
            )
            for option in options
        ]
        request = agent_interaction_manager.create_request(
            session_id=self._session_id,
            user_id=str(self._user_id),
            channel=channel.value,
            source=self._source,
            username=self._username,
            title=title,
            prompt=message.strip(),
            options=choice_options,
        )

        buttons = []
        current_row = []
        for index, option in enumerate(choice_options, start=1):
            current_row.append(
                {
                    "text": self._truncate_button_text(option.label, max_text_length),
                    "callback_data": (
                        f"agent_interaction:choice:{request.request_id}:{index}"
                    ),
                }
            )
            if len(current_row) >= max_per_row:
                buttons.append(current_row)
                current_row = []
        if current_row:
            buttons.append(current_row)

        logger.info(
            "执行工具: %s, channel=%s, session_id=%s, options=%s",
            self.name,
            channel.value,
            self._session_id,
            len(choice_options),
        )

        await ToolChain().async_post_message(
            Notification(
                channel=channel,
                source=self._source,
                mtype=NotificationType.Agent,
                userid=self._user_id,
                username=self._username,
                title=title,
                text=message.strip(),
                buttons=buttons,
            )
        )

        self._agent_context["user_reply_sent"] = True
        self._agent_context["reply_mode"] = "button_choice"
        return f"已发送 {len(choice_options)} 个按钮选项，等待用户选择"
