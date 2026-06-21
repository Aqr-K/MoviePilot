"""发送消息工具"""

import html as html_utils
import re
from typing import Optional, Type

from pydantic import BaseModel, Field, model_validator

from app.agent.tools.base import MoviePilotTool
from app.agent.tools.tags import ToolTag
from app.log import logger
from app.schemas import Notification
from app.schemas.types import NotificationType

SEND_MESSAGE_PARSE_MODE_MARKDOWN = "MarkdownV2"
SEND_MESSAGE_PARSE_MODE_HTML = "HTML"
SEND_MESSAGE_PARSE_MODE_ALIASES = {
    "markdownv2": SEND_MESSAGE_PARSE_MODE_MARKDOWN,
    "mdv2": SEND_MESSAGE_PARSE_MODE_MARKDOWN,
    "html": SEND_MESSAGE_PARSE_MODE_HTML,
}
SEND_MESSAGE_HTML_ALLOWED_TAGS = {
    "a",
    "b",
    "blockquote",
    "code",
    "del",
    "em",
    "i",
    "ins",
    "pre",
    "s",
    "span",
    "strike",
    "strong",
    "tg-spoiler",
    "u",
}
SEND_MESSAGE_HTML_NORMALIZATION_RULES = (
    (re.compile(r"<\s*br\s*/?\s*>", re.IGNORECASE), "\n"),
    (re.compile(r"<\s*/\s*p\s*>", re.IGNORECASE), "\n"),
    (re.compile(r"<\s*p(?:\s+[^>]*)?>", re.IGNORECASE), ""),
    (re.compile(r"<\s*/\s*div\s*>", re.IGNORECASE), "\n"),
    (re.compile(r"<\s*div(?:\s+[^>]*)?>", re.IGNORECASE), ""),
    (re.compile(r"<\s*/\s*li\s*>", re.IGNORECASE), "\n"),
    (re.compile(r"<\s*li(?:\s+[^>]*)?>", re.IGNORECASE), "• "),
    (re.compile(r"<\s*/?\s*(?:ul|ol)(?:\s+[^>]*)?>", re.IGNORECASE), ""),
    (re.compile(r"<\s*h[1-6](?:\s+[^>]*)?>", re.IGNORECASE), "<b>"),
    (re.compile(r"<\s*/\s*h[1-6]\s*>", re.IGNORECASE), "</b>\n"),
)
SEND_MESSAGE_HTML_TAG_PATTERN = re.compile(
    r"<\s*(/?)\s*([a-zA-Z][\w:-]*)\b([^>]*)>"
)
SEND_MESSAGE_HTML_ATTR_PATTERN_TEMPLATE = (
    r"""\b{attr_name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"""
)


class SendMessageInput(BaseModel):
    """发送消息工具的输入参数模型"""

    explanation: Optional[str] = Field(
        None,
        description="Clear explanation of why this tool is being used in the current context",
    )
    message: Optional[str] = Field(
        None,
        description="The message content to send to the user (should be clear and informative)",
    )
    title: Optional[str] = Field(
        None,
        description="Title of the message, a short summary of the message content",
    )
    image_url: Optional[str] = Field(
        None,
        description="Optional image URL to send together with the message on channels that support images (such as Telegram and Slack)",
    )
    parse_mode: Optional[str] = Field(
        None,
        description=(
            "Optional Telegram message body format. Supported values: HTML or MarkdownV2. "
            "Leave empty for default."
        ),
    )

    @model_validator(mode="after")
    def validate_payload(self) -> "SendMessageInput":
        """校验消息内容和可选格式参数。"""
        if not self.message and not self.title and not self.image_url:
            raise ValueError("message、title、image_url 至少需要提供一个")
        self.parse_mode = SendMessageTool.normalize_parse_mode(self.parse_mode)
        if self.parse_mode == SEND_MESSAGE_PARSE_MODE_HTML:
            self.message = SendMessageTool.normalize_html_message(self.message)
        return self


class SendMessageTool(MoviePilotTool):
    """发送普通通知消息给当前用户。"""

    name: str = "send_message"
    tags: list[str] = [
        ToolTag.Write,
        ToolTag.Message,
        ToolTag.Admin,
        ToolTag.TerminalResponse,
    ]
    sends_message: bool = True
    return_direct: bool = True
    description: str = (
        "Send notification message to the user through configured notification channels "
        "(Telegram, Slack, WeChat, etc.). Supports optional image_url on channels that can "
        "send images. For Telegram, the optional parse_mode parameter controls message body "
        "rendering. Supported values are HTML and MarkdownV2; leave it empty for default. "
        "This is a terminal response tool: after it sends the user-facing message, do not "
        "send another final text reply with the same content."
    )
    args_schema: Type[BaseModel] = SendMessageInput
    require_admin: bool = True

    @staticmethod
    def normalize_parse_mode(parse_mode: Optional[str]) -> Optional[str]:
        """
        规范化 send_message 支持的 Telegram 格式参数。
        """
        if not parse_mode:
            return None
        normalized = SEND_MESSAGE_PARSE_MODE_ALIASES.get(str(parse_mode).strip().lower())
        if not normalized:
            raise ValueError("parse_mode 仅支持 MarkdownV2 或 HTML")
        return normalized

    @staticmethod
    def _extract_html_attr(attrs: str, attr_name: str) -> Optional[str]:
        """
        从 HTML 标签属性中提取指定属性值。
        """
        pattern = SEND_MESSAGE_HTML_ATTR_PATTERN_TEMPLATE.format(
            attr_name=re.escape(attr_name)
        )
        match = re.search(pattern, attrs or "", re.IGNORECASE)
        if not match:
            return None
        return next((value for value in match.groups() if value is not None), None)

    @staticmethod
    def _normalize_html_tag(match: re.Match) -> str:
        """
        规范化 Telegram 支持的 HTML 标签，并剥离不支持的属性。
        """
        closing, tag_name, attrs = match.groups()
        tag_name = tag_name.lower()
        if tag_name not in SEND_MESSAGE_HTML_ALLOWED_TAGS:
            raise ValueError(f"HTML 标签 <{tag_name}> 不受 Telegram 支持")

        if closing:
            return f"</{tag_name}>"

        if tag_name == "a":
            href = SendMessageTool._extract_html_attr(attrs, "href")
            if not href:
                raise ValueError("HTML 标签 <a> 必须包含 href 属性")
            return f'<a href="{html_utils.escape(href, quote=True)}">'

        if tag_name == "span":
            class_name = SendMessageTool._extract_html_attr(attrs, "class")
            if class_name != "tg-spoiler":
                raise ValueError('HTML 标签 <span> 仅支持 class="tg-spoiler"')
            return '<span class="tg-spoiler">'

        if tag_name == "blockquote":
            if re.search(r"(^|\s)expandable(\s|/|$)", attrs or "", re.IGNORECASE):
                return "<blockquote expandable>"
            return "<blockquote>"

        if tag_name == "code":
            class_name = SendMessageTool._extract_html_attr(attrs, "class")
            if class_name and class_name.startswith("language-"):
                escaped_class = html_utils.escape(class_name, quote=True)
                return f'<code class="{escaped_class}">'
            return "<code>"

        return f"<{tag_name}>"

    @staticmethod
    def normalize_html_message(message: Optional[str]) -> Optional[str]:
        """
        规范化 Agent 生成的 Telegram HTML 正文。
        """
        if not message:
            return message
        normalized = message
        for pattern, replacement in SEND_MESSAGE_HTML_NORMALIZATION_RULES:
            normalized = pattern.sub(replacement, normalized)
        return SEND_MESSAGE_HTML_TAG_PATTERN.sub(
            SendMessageTool._normalize_html_tag, normalized
        )

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据消息参数生成友好的提示消息"""
        message = kwargs.get("message", "") or ""
        title = kwargs.get("title") or ""
        image_url = kwargs.get("image_url")

        # 截断过长的消息
        if len(message) > 50:
            message = message[:50] + "..."

        if title and image_url:
            return f"发送图文消息: [{title}] {message}"
        if title:
            return f"发送消息: [{title}] {message}"
        if image_url:
            return f"发送图片消息: {message}"
        return f"发送消息: {message}"

    async def run(
        self,
        message: Optional[str] = None,
        title: Optional[str] = None,
        image_url: Optional[str] = None,
        parse_mode: Optional[str] = None,
        **kwargs,
    ) -> str:
        """发送消息到当前会话渠道。"""
        title = title or ("图片" if image_url and not message else "")
        text = message or ""
        try:
            parse_mode = self.normalize_parse_mode(parse_mode)
            if parse_mode == SEND_MESSAGE_PARSE_MODE_HTML:
                text = self.normalize_html_message(text) or ""
        except ValueError as e:
            return str(e)

        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, message={text}, "
            f"image_url={image_url}, parse_mode={parse_mode}"
        )
        try:
            await self.send_notification_message(
                Notification(
                    channel=self._channel,
                    source=self._source,
                    mtype=NotificationType.Other,
                    userid=self._user_id,
                    username=self._username,
                    title=title,
                    text=text,
                    image=image_url,
                    parse_mode=parse_mode,
                )
            )
            self._agent_context["user_reply_sent"] = True
            self._agent_context["reply_mode"] = "send_message"
            return "消息已发送"
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return f"发送消息时发生错误: {str(e)}"
