import json
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple

import lark_oapi as lark
from lark_oapi.api.im.v1 import (
    CreateMessageRequest,
    CreateMessageRequestBody,
    P2ImMessageReceiveV1,
    UpdateMessageRequest,
    UpdateMessageRequestBody,
)
from lark_oapi.card.model import Card
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
from app.schemas.types import MessageChannel
from app.utils.http import RequestUtils


class Feishu:
    """飞书通知客户端，负责长连接收消息与主动发送通知。"""

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
        self._user_chat_mapping: Dict[str, str] = {}
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

    def _extract_message_text(self, message) -> str:
        """从飞书事件消息体中提取可读文本。"""
        raw_content = getattr(message, "content", None)
        if not raw_content:
            return ""
        try:
            content = json.loads(raw_content)
        except Exception:
            return ""
        if not isinstance(content, dict):
            return ""
        if isinstance(content.get("text"), str):
            return content.get("text", "").strip()
        return ""

    def _remember_target(self, userid: Optional[str], chat_id: Optional[str]) -> None:
        """记录最近互动的用户与会话映射，便于后续主动回复。"""
        normalized_userid = (userid or "").strip()
        normalized_chat_id = (chat_id or "").strip()
        if not normalized_userid or not normalized_chat_id:
            return
        self._user_chat_mapping[normalized_userid] = normalized_chat_id
        self._chat_open_mapping[normalized_chat_id] = normalized_userid

    def _on_message(self, data: P2ImMessageReceiveV1) -> None:
        """处理飞书长连接收到的普通消息事件。"""
        event = getattr(data, "event", None)
        sender = getattr(event, "sender", None)
        message = getattr(event, "message", None)
        sender_id = getattr(sender, "sender_id", None)
        open_id = getattr(sender_id, "open_id", None)
        user_id = getattr(sender_id, "user_id", None)
        chat_id = getattr(message, "chat_id", None)
        text = self._extract_message_text(message)

        payload = {
            "type": "message",
            "source": self._name,
            "message_id": getattr(message, "message_id", None),
            "chat_id": chat_id,
            "chat_type": getattr(message, "chat_type", None),
            "text": text,
            "sender": {
                "open_id": open_id,
                "user_id": user_id,
                "name": open_id or user_id,
            },
        }
        userid = open_id or user_id
        self._remember_target(userid=userid, chat_id=chat_id)
        logger.info(
            "收到来自 %s 的飞书消息：userid=%s, chat_id=%s, text=%s",
            self._name,
            userid,
            chat_id,
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

    def get_state(self) -> bool:
        """返回飞书客户端是否已就绪。"""
        return self._ready.is_set() and self._api_client is not None

    def stop(self) -> None:
        """停止飞书客户端并结束长连接线程。"""
        self._stop_event.set()
        self._ready.clear()
        ws_client = self._ws_client
        if ws_client:
            try:
                ws_client._auto_reconnect = False
                if ws_client._conn is not None:
                    try:
                        ws_client._conn.close()
                    except Exception as err:
                        logger.debug(f"关闭飞书连接失败：{err}")
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
        if not text:
            return None

        if text.startswith("/") and self._admins and str(userid) not in self._admins:
            self.send_text("只有管理员才有权限执行此命令", userid=str(userid))
            return None

        return CommingMessage(
            channel=MessageChannel.Feishu,
            source=self._name,
            userid=userid,
            username=username,
            text=text,
            message_id=message.get("message_id"),
            chat_id=message.get("chat_id"),
        )

    def _resolve_target(self, userid: Optional[str] = None, chat_id: Optional[str] = None) -> Tuple[str, str]:
        """解析飞书发送目标，优先走显式用户，其次回退默认配置。"""
        resolved_userid = (userid or "").strip() or None
        resolved_chat_id = (chat_id or "").strip() or None
        if not resolved_userid and not resolved_chat_id:
            resolved_userid = self._default_open_id
            resolved_chat_id = self._default_chat_id
        if resolved_userid:
            return resolved_userid, "open_id"
        if resolved_chat_id:
            return resolved_chat_id, "chat_id"
        raise ValueError("未找到可发送的飞书目标")

    @staticmethod
    def _build_message_text(title: Optional[str], text: Optional[str], link: Optional[str] = None) -> str:
        """拼接飞书 Markdown 文本内容。"""
        parts = []
        if title:
            parts.append(f"**{title.strip()}**")
        if text:
            parts.append(text.strip())
        if link:
            parts.append(f"[查看详情]({link})")
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
        content = self._build_message_text(title=title, text=text, link=link)
        elements: List[dict] = []
        if content:
            elements.append({"tag": "markdown", "content": content})
        elements.extend(self._card_actions(buttons))
        return {
            "config": {"wide_screen_mode": True, "enable_forward": True},
            "elements": elements,
        }

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
        }

    def send_text(self, text: str, userid: Optional[str] = None, chat_id: Optional[str] = None) -> Optional[dict]:
        """发送纯文本消息。"""
        try:
            receive_id, receive_id_type = self._resolve_target(userid=userid, chat_id=chat_id)
            result = self._send_message(receive_id, receive_id_type, "text", {"text": text})
        except Exception as err:
            logger.error(f"飞书文本消息发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def send_notification(self, message: Notification, userid: Optional[str] = None, chat_id: Optional[str] = None) -> Optional[dict]:
        """发送通知消息，优先使用交互卡片承载按钮。"""
        payload = self._build_card(
            title=message.title,
            text=message.text,
            link=message.link,
            buttons=message.buttons,
        )
        try:
            receive_id, receive_id_type = self._resolve_target(userid=userid, chat_id=chat_id)
            result = self._send_message(receive_id, receive_id_type, "interactive", {"card": payload})
        except Exception as err:
            logger.error(f"飞书通知发送失败：{err}")
            return {"success": False}

        if not result:
            return {"success": False}
        result["chat_id"] = result.get("chat_id") or chat_id or self._user_chat_mapping.get(userid or "") or self._default_chat_id
        return result

    def edit_message(self, message_id: str, title: Optional[str] = None, text: Optional[str] = None, buttons: Optional[List[List[dict]]] = None) -> bool:
        """编辑已发送的飞书交互卡片消息。"""
        if not self._api_client:
            return False

        card = self._build_card(title=title, text=text, link=None, buttons=buttons)
        try:
            response = self._api_client.im.v1.message.update(
                UpdateMessageRequest.builder()
                .message_id(message_id)
                .request_body(
                    UpdateMessageRequestBody.builder()
                    .msg_type("interactive")
                    .content(json.dumps({"card": card}, ensure_ascii=False))
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

    def send_medias_message(self, message: Notification, medias: List[MediaInfo]) -> Optional[dict]:
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
        return self.send_notification(proxy_message, userid=message.userid)

    def send_torrents_message(self, message: Notification, torrents: List[Context]) -> Optional[dict]:
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
        return self.send_notification(proxy_message, userid=message.userid)
