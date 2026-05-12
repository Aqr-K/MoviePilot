import asyncio
import base64
import json
import mimetypes
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import lark_oapi as lark
import lark_oapi.ws.client as lark_ws_client_module
from lark_oapi.api.cardkit.v1 import (
    ContentCardElementRequest,
    ContentCardElementRequestBody,
    CreateCardRequest,
    CreateCardRequestBody,
    SettingsCardRequest,
    SettingsCardRequestBody,
)
from lark_oapi.api.im.v1 import (
    CreateFileRequest,
    CreateFileRequestBody,
    CreateImageRequest,
    CreateImageRequestBody,
    CreateMessageRequest,
    CreateMessageRequestBody,
    CreateMessageReactionRequest,
    CreateMessageReactionRequestBody,
    DeleteMessageReactionRequest,
    GetFileRequest,
    GetImageRequest,
    GetMessageResourceRequest,
    PatchMessageRequest,
    PatchMessageRequestBody,
    P2ImMessageMessageReadV1,
    P2ImMessageReceiveV1,
    ReplyMessageRequest,
    ReplyMessageRequestBody,
    Emoji,
)
from lark_oapi.core.const import FEISHU_DOMAIN
from lark_oapi.core.enum import LogLevel
from lark_oapi.event.callback.model.p2_card_action_trigger import (
    P2CardActionTrigger,
    P2CardActionTriggerResponse,
)

from app.core.config import settings
from app.core.context import Context, MediaInfo
from app.log import logger
from app.schemas import CommingMessage, Notification
from app.schemas.types import MessageChannel, NotificationType
from app.utils.http import RequestUtils


class Feishu:
    """飞书通知客户端，负责长连接收消息与主动发送通知。"""

    PROCESSING_REACTION_EMOJI = "GLANCE"
    STREAM_CARD_TITLE_ELEMENT_ID = "mp_stream_title"
    STREAM_CARD_BODY_ELEMENT_ID = "mp_stream_body"

    def __init__(
        self,
        FEISHU_APP_ID: Optional[str] = None,
        FEISHU_APP_SECRET: Optional[str] = None,
        FEISHU_OPEN_ID: Optional[str] = None,
        FEISHU_CHAT_ID: Optional[str] = None,
        FEISHU_ADMINS: Optional[str] = None,
        FEISHU_VERIFICATION_TOKEN: Optional[str] = None,
        FEISHU_ENCRYPT_KEY: Optional[str] = None,
        name: Optional[str] = None,
        **kwargs,
    ):
        """初始化飞书客户端与长连接所需配置。"""
        self._name = name or "feishu"
        self._app_id = (FEISHU_APP_ID or "").strip()
        self._app_secret = (FEISHU_APP_SECRET or "").strip()
        self._default_open_id = (FEISHU_OPEN_ID or "").strip() or None
        self._default_chat_id = (FEISHU_CHAT_ID or "").strip() or None
        self._admins = [item.strip() for item in (FEISHU_ADMINS or "").split(",") if item.strip()]
        self._verification_token = (FEISHU_VERIFICATION_TOKEN or "").strip()
        self._encrypt_key = (FEISHU_ENCRYPT_KEY or "").strip()

        self._api_client: Optional[lark.Client] = None
        self._ws_client: Optional[lark.ws.Client] = None
        self._ready = threading.Event()
        self._stop_event = threading.Event()
        self._ws_thread: Optional[threading.Thread] = None
        self._ws_loop: Optional[asyncio.AbstractEventLoop] = None
        self._user_chat_mapping: Dict[str, str] = {}
        self._user_receive_id_type_mapping: Dict[str, str] = {}
        self._chat_open_mapping: Dict[str, str] = {}

        if not self._app_id or not self._app_secret:
            logger.error("飞书配置不完整：缺少 App ID 或 App Secret")
            return

        self._api_client = self._build_api_client()
        self._start_ws_client()

    def _build_api_client(self) -> lark.Client:
        """构建飞书 OpenAPI client，用于发送和编辑消息。"""
        return (
            lark.Client.builder()
            .app_id(self._app_id)
            .app_secret(self._app_secret)
            .domain(FEISHU_DOMAIN)
            .log_level(LogLevel.INFO)
            .build()
        )

    def _build_event_handler(self) -> lark.EventDispatcherHandler:
        """构建飞书事件分发器，将消息与卡片回调接到本地消息链。"""
        builder = lark.EventDispatcherHandler.builder(
            self._encrypt_key,
            self._verification_token,
            level=LogLevel.INFO,
        )
        builder.register_p2_im_message_receive_v1(self._on_message)
        builder.register_p2_im_message_message_read_v1(self._on_message_read)
        builder.register_p2_card_action_trigger(self._on_card_action)
        return builder.build()

    def _start_ws_client(self) -> None:
        """启动飞书长连接客户端线程。"""
        if self._ws_thread and self._ws_thread.is_alive():
            return

        self._stop_event.clear()
        self._ws_thread = threading.Thread(target=self._run_ws_client, daemon=True)
        self._ws_thread.start()

    def _run_ws_client(self) -> None:
        """在后台线程中运行飞书长连接客户端。"""
        original_select = lark_ws_client_module._select
        original_loop = lark_ws_client_module.loop
        loop = asyncio.new_event_loop()
        self._ws_loop = loop
        asyncio.set_event_loop(loop)
        lark_ws_client_module.loop = loop

        async def _wait_for_stop() -> None:
            while not self._stop_event.is_set():
                await asyncio.sleep(1)

        lark_ws_client_module._select = _wait_for_stop
        try:
            self._ws_client = lark.ws.Client(
                self._app_id,
                self._app_secret,
                log_level=LogLevel.INFO,
                event_handler=self._build_event_handler(),
                domain=FEISHU_DOMAIN,
                auto_reconnect=True,
            )
            self._ready.set()
            logger.info("飞书长连接服务启动：%s", self._name)
            self._ws_client.start()
        except Exception as err:
            self._ready.clear()
            if not self._stop_event.is_set():
                logger.error(f"飞书长连接服务启动失败：{err}")
        finally:
            lark_ws_client_module._select = original_select
            lark_ws_client_module.loop = original_loop
            pending_tasks = [
                task
                for task in asyncio.all_tasks(loop)
                if not task.done()
            ]
            for task in pending_tasks:
                task.cancel()
            if pending_tasks:
                loop.run_until_complete(
                    asyncio.gather(*pending_tasks, return_exceptions=True)
                )
            loop.close()
            asyncio.set_event_loop(None)
            self._ws_loop = None

    def _forward_to_message_chain(self, payload: dict) -> None:
        """将飞书入站消息转发到统一消息入口，复用现有交互主链。"""

        def _run() -> None:
            try:
                RequestUtils(timeout=15).post_res(
                    f"http://127.0.0.1:{settings.PORT}/api/v1/message?token={settings.API_TOKEN}&source={self._name}",
                    json=payload,
                )
            except Exception as err:
                logger.error(f"飞书转发消息失败：{err}")

        threading.Thread(target=_run, daemon=True).start()

    @staticmethod
    def _parse_message_content(message) -> Tuple[str, Optional[List[CommingMessage.MessageImage]], Optional[List[str]], Optional[List[CommingMessage.MessageAttachment]]]:
        """从飞书事件消息体中提取文本、图片、音频和文件引用。"""
        raw_content = getattr(message, "content", None)
        if not raw_content:
            return "", None, None, None
        try:
            content = json.loads(raw_content)
        except Exception:
            return "", None, None, None
        if not isinstance(content, dict):
            return "", None, None, None

        message_type = getattr(message, "message_type", None)
        text = content.get("text", "").strip() if isinstance(content.get("text"), str) else ""
        images = None
        audio_refs = None
        files = None

        if message_type == "image":
            image_key = str(content.get("image_key") or "").strip()
            message_id = str(getattr(message, "message_id", None) or "").strip()
            if image_key:
                if message_id:
                    images = [CommingMessage.MessageImage(ref=f"feishu://image/{message_id}/{image_key}")]
                else:
                    images = [CommingMessage.MessageImage(ref=f"feishu://image/{image_key}")]
        elif message_type in {"audio", "media", "file"}:
            file_key = str(content.get("file_key") or "").strip()
            file_name = str(content.get("file_name") or "").strip() or None
            if file_key:
                if message_type == "audio":
                    audio_refs = [f"feishu://file/{file_key}/{file_name or 'audio.opus'}"]
                else:
                    files = [
                        CommingMessage.MessageAttachment(
                            ref=f"feishu://file/{file_key}/{file_name or 'attachment'}",
                            name=file_name,
                        )
                    ]

        return text, images, audio_refs, files

    def _remember_target(self, userid: Optional[str], chat_id: Optional[str]) -> None:
        """记录最近互动的用户与会话映射，便于后续主动回复。"""
        normalized_userid = (userid or "").strip()
        normalized_chat_id = (chat_id or "").strip()
        if not normalized_userid or not normalized_chat_id:
            return
        self._user_chat_mapping[normalized_userid] = normalized_chat_id
        self._chat_open_mapping[normalized_chat_id] = normalized_userid

    def _remember_user_id_type(
        self,
        open_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> None:
        """记住用户对应的飞书 ID 类型，避免回消息时误用 open_id/user_id。"""
        normalized_open_id = (open_id or "").strip()
        normalized_user_id = (user_id or "").strip()
        if normalized_open_id:
            self._user_receive_id_type_mapping[normalized_open_id] = "open_id"
        if normalized_user_id:
            self._user_receive_id_type_mapping[normalized_user_id] = "user_id"

    def _on_message(self, data: P2ImMessageReceiveV1) -> None:
        """处理飞书长连接收到的普通消息事件。"""
        event = getattr(data, "event", None)
        sender = getattr(event, "sender", None)
        message = getattr(event, "message", None)
        sender_id = getattr(sender, "sender_id", None)
        open_id = getattr(sender_id, "open_id", None)
        user_id = getattr(sender_id, "user_id", None)
        chat_id = getattr(message, "chat_id", None)
        text, images, audio_refs, files = self._parse_message_content(message)
        message_type = getattr(message, "message_type", None)

        payload = {
            "type": "message",
            "source": self._name,
            "message_id": getattr(message, "message_id", None),
            "chat_id": chat_id,
            "chat_type": getattr(message, "chat_type", None),
            "message_type": message_type,
            "text": text,
            "images": [image.model_dump() for image in images] if images else None,
            "audio_refs": audio_refs,
            "files": [file.model_dump() for file in files] if files else None,
            "sender": {
                "open_id": open_id,
                "user_id": user_id,
                "name": open_id or user_id,
            },
        }
        userid = open_id or user_id
        self._remember_user_id_type(open_id=open_id, user_id=user_id)
        self._remember_target(userid=userid, chat_id=chat_id)
        logger.info(
            "收到来自 %s 的飞书消息：userid=%s, chat_id=%s, type=%s, text=%s",
            self._name,
            userid,
            chat_id,
            message_type,
            text,
        )
        self._forward_to_message_chain(payload)

    def _on_card_action(self, data: P2CardActionTrigger) -> P2CardActionTriggerResponse:
        """处理飞书卡片按钮回调，并同步回统一消息链。"""
        event = getattr(data, "event", None)
        operator = getattr(event, "operator", None)
        action = getattr(event, "action", None)
        context = getattr(event, "context", None)
        value = getattr(action, "value", None) or {}
        callback_data = None
        if isinstance(value, dict):
            callback_data = value.get("callback_data") or value.get("value")
        if not callback_data:
            callback_data = getattr(action, "name", None)

        payload = {
            "type": "cardAction",
            "source": self._name,
            "message_id": getattr(context, "open_message_id", None),
            "chat_id": getattr(context, "open_chat_id", None),
            "callback_data": callback_data,
            "sender": {
                "open_id": getattr(operator, "open_id", None),
                "user_id": getattr(operator, "user_id", None),
                "name": getattr(operator, "open_id", None) or getattr(operator, "user_id", None),
            },
        }
        userid = payload["sender"].get("open_id") or payload["sender"].get("user_id")
        self._remember_user_id_type(
            open_id=payload["sender"].get("open_id"),
            user_id=payload["sender"].get("user_id"),
        )
        self._remember_target(userid=userid, chat_id=payload.get("chat_id"))
        logger.info(
            "收到来自 %s 的飞书按钮回调：userid=%s, callback_data=%s",
            self._name,
            userid,
            callback_data,
        )
        self._forward_to_message_chain(payload)

        return P2CardActionTriggerResponse(
            {
                "toast": {
                    "type": "info",
                    "content": "操作已提交",
                }
            }
        )

    @staticmethod
    def _on_message_read(data: P2ImMessageMessageReadV1) -> None:
        """忽略消息已读事件，避免长连接打印未注册处理器错误。"""
        event = getattr(data, "event", None)
        reader = getattr(event, "reader", None)
        logger.debug(
            "收到飞书消息已读事件：reader=%s, message_count=%s",
            getattr(reader, "open_id", None) or getattr(reader, "user_id", None),
            len(getattr(event, "message_id_list", None) or []),
        )

    def get_state(self) -> bool:
        """返回飞书客户端是否已就绪。"""
        return self._ready.is_set() and self._api_client is not None

    def stop(self) -> None:
        """停止飞书客户端并结束长连接线程。"""
        self._stop_event.set()
        self._ready.clear()
        ws_client = self._ws_client
        ws_loop = self._ws_loop
        if ws_client:
            try:
                ws_client._auto_reconnect = False
                if ws_loop and ws_loop.is_running():
                    disconnect_future = asyncio.run_coroutine_threadsafe(
                        ws_client._disconnect(),
                        ws_loop,
                    )
                    disconnect_future.result(timeout=5)
            except Exception as err:
                logger.debug(f"停止飞书客户端失败：{err}")
        if self._ws_thread and self._ws_thread.is_alive():
            self._ws_thread.join(timeout=5)

    def parse_message(self, body: Any) -> Optional[CommingMessage]:
        """解析飞书转发到消息入口的 JSON 报文。"""
        try:
            message = json.loads(body) if isinstance(body, (str, bytes, bytearray)) else body
        except Exception as err:
            logger.debug(f"解析飞书消息失败：{err}")
            return None

        if not isinstance(message, dict):
            return None

        sender = message.get("sender") or {}
        open_id = sender.get("open_id")
        user_id = sender.get("user_id")
        username = sender.get("name") or open_id or user_id
        userid = open_id or user_id
        if not userid:
            return None

        if message.get("type") == "cardAction":
            callback_data = message.get("callback_data")
            if not callback_data:
                return None
            return CommingMessage(
                channel=MessageChannel.Feishu,
                source=self._name,
                userid=userid,
                username=username,
                text=f"CALLBACK:{callback_data}",
                is_callback=True,
                callback_data=callback_data,
                message_id=message.get("message_id"),
                chat_id=message.get("chat_id"),
            )

        text = (message.get("text") or "").strip()
        images = CommingMessage.MessageImage.normalize_list(message.get("images"))
        audio_refs = None
        if isinstance(message.get("audio_refs"), list):
            audio_refs = [str(item).strip() for item in message.get("audio_refs") if str(item).strip()] or None
        files = None
        if isinstance(message.get("files"), list):
            normalized_files = []
            for item in message.get("files"):
                if isinstance(item, dict) and item.get("ref"):
                    normalized_files.append(CommingMessage.MessageAttachment(**item))
            files = normalized_files or None

        if not text and not images and not audio_refs and not files:
            return None

        if text.startswith("/") and self._admins and str(userid) not in self._admins:
            self.send_text(
                "只有管理员才有权限执行此命令",
                userid=str(userid),
                chat_id=message.get("chat_id"),
                receive_id_type="open_id" if open_id else "user_id",
            )
            return None

        return CommingMessage(
            channel=MessageChannel.Feishu,
            source=self._name,
            userid=userid,
            username=username,
            text=text,
            message_id=message.get("message_id"),
            chat_id=message.get("chat_id"),
            images=images,
            audio_refs=audio_refs,
            files=files,
        )

    def _resolve_target(
        self,
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
    ) -> Tuple[str, str]:
        """解析飞书发送目标，优先走显式用户，其次回退默认配置。"""
        resolved_userid = (userid or "").strip() or None
        resolved_chat_id = (chat_id or "").strip() or None
        normalized_receive_id_type = (receive_id_type or "").strip() or None
        if not resolved_userid and not resolved_chat_id:
            resolved_userid = self._default_open_id
            resolved_chat_id = self._default_chat_id
            if resolved_userid and not normalized_receive_id_type:
                normalized_receive_id_type = "open_id"
        if normalized_receive_id_type == "chat_id" and resolved_chat_id:
            return resolved_chat_id, "chat_id"
        if resolved_userid:
            if normalized_receive_id_type in {"open_id", "user_id"}:
                return resolved_userid, normalized_receive_id_type
            remembered_type = self._user_receive_id_type_mapping.get(resolved_userid)
            return resolved_userid, remembered_type or "open_id"
        if resolved_chat_id:
            return resolved_chat_id, "chat_id"
        raise ValueError("未找到可发送的飞书目标")

    @staticmethod
    def _escape_card_text(text: Optional[str]) -> str:
        """转义飞书卡片 markdown 中易误触的字符。"""
        if not text:
            return ""
        escaped = str(text)
        for source, target in {
            "\\": "&#92;",
            "<": "&#60;",
            ">": "&#62;",
        }.items():
            escaped = escaped.replace(source, target)
        return escaped

    @classmethod
    def _build_markdown_section(cls, text: Optional[str], text_size: str = "normal") -> Optional[dict]:
        content = cls._escape_card_text(text).strip()
        if not content:
            return None
        return {
            "tag": "markdown",
            "text_size": text_size,
            "content": content,
        }

    @staticmethod
    def _build_message_text(title: Optional[str], text: Optional[str], link: Optional[str] = None) -> str:
        """拼接飞书 Markdown 文本内容。"""
        parts = []
        if title:
            parts.append(f"**{Feishu._escape_card_text(title).strip()}**")
        if text:
            parts.append(Feishu._escape_card_text(text).strip())
        if link:
            parts.append(f"[查看详情]({link.strip()})")
        return "\n\n".join(part for part in parts if part)

    @staticmethod
    def _card_actions(buttons: Optional[List[List[dict]]]) -> List[dict]:
        """将统一按钮结构转换为飞书卡片按钮配置。"""
        if not buttons:
            return []
        card_rows = []
        for row in buttons[:8]:
            elements = []
            for button in row[:3]:
                text = (button or {}).get("text")
                if not text:
                    continue
                url = (button or {}).get("url")
                callback_data = (button or {}).get("callback_data")
                value = {"callback_data": callback_data} if callback_data else {"value": text}
                element = {
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": text[:20]},
                    "type": "default",
                    "value": value,
                }
                if url:
                    element["multi_url"] = {
                        "url": url,
                        "pc_url": url,
                        "android_url": url,
                        "ios_url": url,
                    }
                elements.append(element)
            if elements:
                card_rows.append({"tag": "action", "actions": elements})
        return card_rows

    def _build_card(self, title: Optional[str], text: Optional[str], link: Optional[str], buttons: Optional[List[List[dict]]]) -> Dict[str, Any]:
        """构建飞书交互卡片结构。"""
        elements: List[dict] = []
        title_section = self._build_markdown_section(title, text_size="heading")
        body_section = self._build_markdown_section(
            self._build_message_text(title=None, text=text, link=link),
            text_size="normal",
        )
        if title_section:
            elements.append(title_section)
        if body_section:
            elements.append(body_section)
        elements.extend(self._card_actions(buttons))
        return {
            # 飞书卡片消息要支持后续 PATCH 更新，发送和更新时都必须显式声明 update_multi。
            "config": {
                "wide_screen_mode": True,
                "enable_forward": True,
                "update_multi": True,
            },
            "elements": elements,
        }

    def _build_streaming_card_payload(
        self,
        title: Optional[str],
        text: Optional[str],
    ) -> Dict[str, Any]:
        """构建支持 CardKit 流式更新的飞书卡片 JSON 2.0。"""
        elements: List[dict] = []
        title_content = self._escape_card_text(title).strip() if title else ""
        if title_content:
            elements.append(
                {
                    "tag": "markdown",
                    "element_id": self.STREAM_CARD_TITLE_ELEMENT_ID,
                    "content": f"**{title_content}**",
                }
            )
        elements.append(
            {
                "tag": "markdown",
                "element_id": self.STREAM_CARD_BODY_ELEMENT_ID,
                "content": self._escape_card_text(text).strip() or " ",
            }
        )
        return {
            "schema": "2.0",
            "config": {
                "wide_screen_mode": True,
                "enable_forward": True,
                "update_multi": True,
                "streaming_mode": True,
                "summary": {
                    "content": title or "MoviePilot助手",
                },
                "streaming_config": {
                    "print_frequency_ms": {"default": 70},
                    "print_step": {"default": 1},
                    "print_strategy": "fast",
                },
            },
            "body": {
                "direction": "vertical",
                "padding": "12px 12px 12px 12px",
                "elements": elements,
            },
        }

    def _create_streaming_card(self, title: Optional[str], text: Optional[str]) -> Optional[str]:
        if not self._api_client:
            return None
        response = self._api_client.cardkit.v1.card.create(
            CreateCardRequest.builder()
            .request_body(
                CreateCardRequestBody.builder()
                .type("card_json")
                .data(json.dumps(self._build_streaming_card_payload(title=title, text=text), ensure_ascii=False))
                .build()
            )
            .build()
        )
        if response.success():
            data = getattr(response, "data", None)
            return getattr(data, "card_id", None)
        logger.error(
            "飞书流式卡片创建失败：code=%s, msg=%s, log_id=%s",
            response.code,
            response.msg,
            response.get_log_id(),
        )
        return None

    def _send_streaming_card_message(
        self,
        title: Optional[str],
        text: Optional[str],
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
        original_message_id: Optional[str] = None,
    ) -> Optional[dict]:
        card_id = self._create_streaming_card(title=title, text=text)
        if not card_id:
            return None
        if original_message_id:
            result = self._reply_message(
                message_id=original_message_id,
                msg_type="interactive",
                content={"type": "card", "data": {"card_id": card_id}},
            )
        else:
            receive_id, resolved_receive_id_type = self._resolve_target(
                userid=userid,
                chat_id=chat_id,
                receive_id_type=receive_id_type,
            )
            result = self._send_message(
                receive_id,
                resolved_receive_id_type,
                "interactive",
                {"type": "card", "data": {"card_id": card_id}},
            )
        if not result:
            return None
        result["metadata"] = {
            "feishu_streaming": {
                "card_id": card_id,
                "element_id": self.STREAM_CARD_BODY_ELEMENT_ID,
                "sequence": 1,
            }
        }
        return result

    def _update_streaming_card_content(
        self,
        card_id: str,
        element_id: str,
        content: str,
        sequence: int,
    ) -> bool:
        if not self._api_client:
            return False
        response = self._api_client.cardkit.v1.card_element.content(
            ContentCardElementRequest.builder()
            .card_id(card_id)
            .element_id(element_id)
            .request_body(
                ContentCardElementRequestBody.builder()
                .uuid(str(uuid.uuid4()))
                .content(content or " ")
                .sequence(sequence)
                .build()
            )
            .build()
        )
        if response.success():
            return True
        logger.error(
            "飞书流式卡片内容更新失败：card_id=%s, element_id=%s, sequence=%s, code=%s, msg=%s, log_id=%s",
            card_id,
            element_id,
            sequence,
            response.code,
            response.msg,
            response.get_log_id(),
        )
        return False

    def close_streaming_card(self, card_id: str, sequence: int) -> bool:
        if not self._api_client or not card_id:
            return False
        response = self._api_client.cardkit.v1.card.settings(
            SettingsCardRequest.builder()
            .card_id(card_id)
            .request_body(
                SettingsCardRequestBody.builder()
                .settings(json.dumps({"config": {"streaming_mode": False}}, ensure_ascii=False))
                .uuid(str(uuid.uuid4()))
                .sequence(sequence)
                .build()
            )
            .build()
        )
        if response.success():
            return True
        logger.error(
            "飞书关闭流式卡片失败：card_id=%s, sequence=%s, code=%s, msg=%s, log_id=%s",
            card_id,
            sequence,
            response.code,
            response.msg,
            response.get_log_id(),
        )
        return False

    def _send_message(self, receive_id: str, receive_id_type: str, msg_type: str, content: dict) -> Optional[dict]:
        """调用飞书 IM API 发送消息，并返回统一结果结构。"""
        if not self._api_client:
            raise RuntimeError("飞书客户端未初始化")

        request = (
            CreateMessageRequest.builder()
            .receive_id_type(receive_id_type)
            .request_body(
                CreateMessageRequestBody.builder()
                .receive_id(receive_id)
                .msg_type(msg_type)
                .content(json.dumps(content, ensure_ascii=False))
                .uuid(str(uuid.uuid4()))
                .build()
            )
            .build()
        )
        response = self._api_client.im.v1.message.create(request)
        if not response.success():
            logger.error(
                "飞书消息发送失败：code=%s, msg=%s, log_id=%s",
                response.code,
                response.msg,
                response.get_log_id(),
            )
            return None

        data = getattr(response, "data", None)
        return {
            "success": True,
            "message_id": getattr(data, "message_id", None),
            "chat_id": getattr(data, "chat_id", None),
            "msg_type": getattr(data, "msg_type", None),
        }

    def _reply_message(
        self,
        message_id: str,
        msg_type: str,
        content: dict,
        reply_in_thread: bool = False,
    ) -> Optional[dict]:
        """按原消息回复，保持飞书会话中的引用关系。"""
        if not self._api_client:
            raise RuntimeError("飞书客户端未初始化")

        request = (
            ReplyMessageRequest.builder()
            .message_id(message_id)
            .request_body(
                ReplyMessageRequestBody.builder()
                .content(json.dumps(content, ensure_ascii=False))
                .msg_type(msg_type)
                .reply_in_thread(reply_in_thread)
                .uuid(str(uuid.uuid4()))
                .build()
            )
            .build()
        )
        response = self._api_client.im.v1.message.reply(request)
        if not response.success():
            logger.error(
                "飞书回复消息失败：code=%s, msg=%s, log_id=%s",
                response.code,
                response.msg,
                response.get_log_id(),
            )
            return None

        data = getattr(response, "data", None)
        return {
            "success": True,
            "message_id": getattr(data, "message_id", None),
            "chat_id": getattr(data, "chat_id", None),
            "msg_type": getattr(data, "msg_type", None),
            "root_id": getattr(data, "root_id", None),
            "parent_id": getattr(data, "parent_id", None),
            "thread_id": getattr(data, "thread_id", None),
        }

    @staticmethod
    def _guess_file_type(file_path: Path) -> str:
        suffix = file_path.suffix.lower().lstrip(".")
        if suffix == "opus":
            return "opus"
        if suffix == "mp4":
            return "mp4"
        if suffix in {"pdf", "doc", "xls", "ppt"}:
            return suffix
        return "stream"

    def _upload_image(self, file_path: Path) -> Optional[str]:
        if not self._api_client:
            return None
        with file_path.open("rb") as fp:
            response = self._api_client.im.v1.image.create(
                CreateImageRequest.builder()
                .request_body(
                    CreateImageRequestBody.builder()
                    .image_type("message")
                    .image(fp)
                    .build()
                )
                .build()
            )
        if not response.success():
            logger.error(
                "飞书图片上传失败：code=%s, msg=%s, log_id=%s",
                response.code,
                response.msg,
                response.get_log_id(),
            )
            return None
        data = getattr(response, "data", None)
        return getattr(data, "image_key", None)

    def _upload_file(self, file_path: Path, file_name: Optional[str] = None, duration: Optional[int] = None) -> Optional[str]:
        if not self._api_client:
            return None
        with file_path.open("rb") as fp:
            builder = (
                CreateFileRequestBody.builder()
                .file_type(self._guess_file_type(file_path))
                .file_name(file_name or file_path.name)
                .file(fp)
            )
            if duration is not None:
                builder.duration(duration)
            response = self._api_client.im.v1.file.create(
                CreateFileRequest.builder().request_body(builder.build()).build()
            )
        if not response.success():
            logger.error(
                "飞书文件上传失败：code=%s, msg=%s, log_id=%s",
                response.code,
                response.msg,
                response.get_log_id(),
            )
            return None
        data = getattr(response, "data", None)
        return getattr(data, "file_key", None)

    def _download_image_bytes(self, image_key: str) -> Optional[Tuple[bytes, Optional[str], Optional[str]]]:
        if not self._api_client or not image_key:
            return None
        response = self._api_client.im.v1.image.get(
            GetImageRequest.builder().image_key(image_key).build()
        )
        if getattr(response, "code", -1) != 0 or not getattr(response, "file", None):
            return None
        content_type = None
        if getattr(response, "raw", None) and getattr(response.raw, "headers", None):
            content_type = response.raw.headers.get("Content-Type")
        return response.file.read(), response.file_name, content_type

    def _download_file_bytes(self, file_key: str) -> Optional[Tuple[bytes, Optional[str], Optional[str]]]:
        if not self._api_client or not file_key:
            return None
        response = self._api_client.im.v1.file.get(
            GetFileRequest.builder().file_key(file_key).build()
        )
        if getattr(response, "code", -1) != 0 or not getattr(response, "file", None):
            return None
        content_type = None
        if getattr(response, "raw", None) and getattr(response.raw, "headers", None):
            content_type = response.raw.headers.get("Content-Type")
        return response.file.read(), response.file_name, content_type

    def _download_message_resource_bytes(self, message_id: str, file_key: str, resource_type: str) -> Optional[Tuple[bytes, Optional[str], Optional[str]]]:
        if not self._api_client or not message_id or not file_key:
            return None
        response = self._api_client.im.v1.message_resource.get(
            GetMessageResourceRequest.builder()
            .message_id(message_id)
            .file_key(file_key)
            .type(resource_type)
            .build()
        )
        if getattr(response, "code", -1) != 0 or not getattr(response, "file", None):
            return None
        content_type = None
        if getattr(response, "raw", None) and getattr(response.raw, "headers", None):
            content_type = response.raw.headers.get("Content-Type")
        return response.file.read(), response.file_name, content_type

    def send_text(
        self,
        text: str,
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
        original_message_id: Optional[str] = None,
    ) -> Optional[dict]:
        """发送纯文本消息。"""
        try:
            if original_message_id:
                result = self._reply_message(
                    message_id=original_message_id,
                    msg_type="text",
                    content={"text": text},
                )
            else:
                receive_id, resolved_receive_id_type = self._resolve_target(
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )
                result = self._send_message(
                    receive_id,
                    resolved_receive_id_type,
                    "text",
                    {"text": text},
                )
        except Exception as err:
            logger.error(f"飞书文本消息发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def send_file(
        self,
        file_path: str,
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        title: Optional[str] = None,
        text: Optional[str] = None,
        file_name: Optional[str] = None,
        receive_id_type: Optional[str] = None,
        original_message_id: Optional[str] = None,
    ) -> Optional[dict]:
        """发送本地图片或文件。"""
        local_file = Path(file_path)
        if not local_file.exists() or not local_file.is_file():
            logger.error(f"飞书附件不存在：{local_file}")
            return {"success": False}

        suffix = local_file.suffix.lower()
        is_image = suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".heic"}
        try:
            if is_image:
                image_key = self._upload_image(local_file)
                if not image_key:
                    return {"success": False}
                if original_message_id:
                    result = self._reply_message(
                        message_id=original_message_id,
                        msg_type="image",
                        content={"image_key": image_key},
                    )
                else:
                    receive_id, resolved_receive_id_type = self._resolve_target(
                        userid=userid,
                        chat_id=chat_id,
                        receive_id_type=receive_id_type,
                    )
                    result = self._send_message(
                        receive_id,
                        resolved_receive_id_type,
                        "image",
                        {"image_key": image_key},
                    )
            else:
                file_key = self._upload_file(local_file, file_name=file_name)
                if not file_key:
                    return {"success": False}
                if original_message_id:
                    result = self._reply_message(
                        message_id=original_message_id,
                        msg_type="file",
                        content={"file_key": file_key},
                    )
                else:
                    receive_id, resolved_receive_id_type = self._resolve_target(
                        userid=userid,
                        chat_id=chat_id,
                        receive_id_type=receive_id_type,
                    )
                    result = self._send_message(
                        receive_id,
                        resolved_receive_id_type,
                        "file",
                        {"file_key": file_key},
                    )
            if result and (title or text):
                self.send_text(
                    self._build_message_text(title=title, text=text),
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                    original_message_id=original_message_id,
                )
        except Exception as err:
            logger.error(f"飞书附件发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def send_voice(
        self,
        voice_path: str,
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        caption: Optional[str] = None,
        receive_id_type: Optional[str] = None,
        original_message_id: Optional[str] = None,
    ) -> Optional[dict]:
        """发送飞书语音消息。"""
        local_file = Path(voice_path)
        if not local_file.exists() or not local_file.is_file():
            logger.error(f"飞书语音文件不存在：{local_file}")
            return {"success": False}

        try:
            file_key = self._upload_file(local_file, file_name=local_file.name)
            if not file_key:
                return {"success": False}
            if original_message_id:
                result = self._reply_message(
                    message_id=original_message_id,
                    msg_type="audio",
                    content={"file_key": file_key},
                )
            else:
                receive_id, resolved_receive_id_type = self._resolve_target(
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )
                result = self._send_message(
                    receive_id,
                    resolved_receive_id_type,
                    "audio",
                    {"file_key": file_key},
                )
            if result and caption:
                self.send_text(
                    caption,
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                    original_message_id=original_message_id,
                )
        except Exception as err:
            logger.error(f"飞书语音消息发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def send_notification(
        self,
        message: Notification,
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
        original_message_id: Optional[str] = None,
    ) -> Optional[dict]:
        """发送通知消息，优先使用交互卡片承载按钮。"""
        is_streaming_agent_text = (
            message.mtype == NotificationType.Agent
            and not message.buttons
            and not message.link
        )
        if is_streaming_agent_text:
            try:
                result = self._send_streaming_card_message(
                    title=message.title,
                    text=message.text,
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                    original_message_id=original_message_id,
                )
            except Exception as err:
                logger.error(f"飞书流式卡片发送失败：{err}")
                return {"success": False}
            if not result:
                return {"success": False}
            result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
            return result

        payload = self._build_card(
            title=message.title,
            text=message.text,
            link=message.link,
            buttons=message.buttons,
        )
        try:
            if original_message_id:
                result = self._reply_message(
                    message_id=original_message_id,
                    msg_type="interactive",
                    content=payload,
                )
            else:
                receive_id, resolved_receive_id_type = self._resolve_target(
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )
                result = self._send_message(
                    receive_id,
                    resolved_receive_id_type,
                    "interactive",
                    payload,
                )
        except Exception as err:
            logger.error(f"飞书通知发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def edit_message(self, message_id: str, title: Optional[str] = None, text: Optional[str] = None, buttons: Optional[List[List[dict]]] = None, metadata: Optional[dict] = None) -> bool:
        """编辑已发送的飞书交互卡片消息。"""
        if not self._api_client:
            return False

        stream_meta = (metadata or {}).get("feishu_streaming") if isinstance(metadata, dict) else None
        if isinstance(stream_meta, dict) and not buttons:
            card_id = str(stream_meta.get("card_id") or "").strip()
            element_id = str(stream_meta.get("element_id") or self.STREAM_CARD_BODY_ELEMENT_ID).strip()
            sequence = int(stream_meta.get("sequence") or 1) + 1
            if card_id and element_id and self._update_streaming_card_content(
                card_id=card_id,
                element_id=element_id,
                content=self._escape_card_text(text).strip() or " ",
                sequence=sequence,
            ):
                stream_meta["sequence"] = sequence
                return True

        card = self._build_card(title=title, text=text, link=None, buttons=buttons)
        try:
            response = self._api_client.im.v1.message.patch(
                PatchMessageRequest.builder()
                .message_id(message_id)
                .request_body(
                    PatchMessageRequestBody.builder()
                    .content(json.dumps(card, ensure_ascii=False))
                    .build()
                )
                .build()
            )
            if response.success():
                return True
            logger.error(
                "飞书消息更新失败：code=%s, msg=%s, log_id=%s",
                response.code,
                response.msg,
                response.get_log_id(),
            )
        except Exception as err:
            logger.error(f"飞书消息更新失败：{err}")
        return False

    def add_message_reaction(
        self,
        message_id: str,
        emoji_type: str,
    ) -> Optional[str]:
        """为指定消息添加表情回应，并返回 reaction_id。"""
        if not self._api_client or not message_id or not emoji_type:
            return None

        try:
            response = self._api_client.im.v1.message_reaction.create(
                CreateMessageReactionRequest.builder()
                .message_id(message_id)
                .request_body(
                    CreateMessageReactionRequestBody.builder()
                    .reaction_type(
                        Emoji.builder().emoji_type(emoji_type).build()
                    )
                    .build()
                )
                .build()
            )
            if not response.success():
                logger.error(
                    "飞书消息表情添加失败：message_id=%s, emoji_type=%s, code=%s, msg=%s, log_id=%s",
                    message_id,
                    emoji_type,
                    response.code,
                    response.msg,
                    response.get_log_id(),
                )
                return None
            data = getattr(response, "data", None)
            return getattr(data, "reaction_id", None)
        except Exception as err:
            logger.error(f"飞书消息表情添加失败：{err}")
            return None

    def delete_message_reaction(self, message_id: str, reaction_id: str) -> bool:
        """删除指定消息上的表情回应。"""
        if not self._api_client or not message_id or not reaction_id:
            return False

        try:
            response = self._api_client.im.v1.message_reaction.delete(
                DeleteMessageReactionRequest.builder()
                .message_id(message_id)
                .reaction_id(reaction_id)
                .build()
            )
            if response.success():
                return True
            logger.error(
                "飞书消息表情删除失败：message_id=%s, reaction_id=%s, code=%s, msg=%s, log_id=%s",
                message_id,
                reaction_id,
                response.code,
                response.msg,
                response.get_log_id(),
            )
        except Exception as err:
            logger.error(f"飞书消息表情删除失败：{err}")
        return False

    def send_medias_message(
        self,
        message: Notification,
        medias: List[MediaInfo],
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
    ) -> Optional[dict]:
        """发送媒体列表消息，复用通知发送链路。"""
        lines = []
        for index, media in enumerate(medias[:10], start=1):
            title = getattr(media, "title_year", None) or getattr(media, "title", None) or "未知媒体"
            lines.append(f"{index}. {title}")
        proxy_message = Notification(
            title=message.title,
            text="\n".join(lines),
            link=message.link,
            buttons=message.buttons,
            userid=message.userid,
            targets=message.targets,
        )
        return self.send_notification(
            proxy_message,
            userid=userid or message.userid,
            chat_id=chat_id,
            receive_id_type=receive_id_type,
        )

    def send_torrents_message(
        self,
        message: Notification,
        torrents: List[Context],
        userid: Optional[str] = None,
        chat_id: Optional[str] = None,
        receive_id_type: Optional[str] = None,
    ) -> Optional[dict]:
        """发送种子列表消息，复用通知发送链路。"""
        lines = []
        for index, torrent in enumerate(torrents[:10], start=1):
            torrent_info = getattr(torrent, "torrent_info", None)
            title = getattr(torrent_info, "title", None) or getattr(torrent_info, "site_name", None) or "未知种子"
            lines.append(f"{index}. {title}")
        proxy_message = Notification(
            title=message.title,
            text="\n".join(lines),
            link=message.link,
            buttons=message.buttons,
            userid=message.userid,
            targets=message.targets,
        )
        return self.send_notification(
            proxy_message,
            userid=userid or message.userid,
            chat_id=chat_id,
            receive_id_type=receive_id_type,
        )
