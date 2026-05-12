from typing import Any, List, Optional, Tuple, Union

from app.core.context import Context, MediaInfo
from app.log import logger
from app.modules import _ModuleBase, _MessageBase
from app.modules.feishu.feishu import Feishu
from app.schemas import CommingMessage, MessageChannel, MessageResponse, Notification
from app.schemas.types import ModuleType


class FeishuModule(_ModuleBase, _MessageBase[Feishu]):
    def init_module(self) -> None:
        self.stop()
        super().init_service(service_name=Feishu.__name__.lower(), service_type=Feishu)
        self._channel = MessageChannel.Feishu

    @staticmethod
    def get_name() -> str:
        return "飞书"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Notification

    @staticmethod
    def get_subtype() -> MessageChannel:
        return MessageChannel.Feishu

    @staticmethod
    def get_priority() -> int:
        return 2

    def stop(self):
        for client in self.get_instances().values():
            if hasattr(client, "stop"):
                try:
                    client.stop()
                except Exception as err:
                    logger.error(f"停止飞书模块实例失败：{err}")

    def test(self) -> Optional[Tuple[bool, str]]:
        if not self.get_instances():
            return None
        for name, client in self.get_instances().items():
            state = client.get_state()
            if not state:
                return False, f"飞书 {name} 未就绪"
        return True, ""

    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        """通知模块通过系统通知配置控制实例化，这里不额外设置环境开关。"""
        return None

    @staticmethod
    def _resolve_message_target(
            message: Notification,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """优先使用 open_id，其次回退 user_id 或 chat_id。"""
        userid = str(message.userid).strip() if message.userid else None
        chat_id = None
        receive_id_type = "open_id" if userid else None

        targets = message.targets or {}
        if not userid and targets:
            open_id = str(targets.get("feishu_openid") or "").strip() or None
            user_id = str(targets.get("feishu_userid") or "").strip() or None
            chat_id = str(targets.get("feishu_chat_id") or "").strip() or None
            if open_id:
                userid = open_id
                receive_id_type = "open_id"
            elif user_id:
                userid = user_id
                receive_id_type = "user_id"

        return userid, chat_id, receive_id_type

    def message_parser(
            self, source: str, body: Any, form: Any, args: Any
    ) -> Optional[CommingMessage]:
        client_config = self.get_config(source)
        if not client_config:
            return None
        client: Feishu = self.get_instance(client_config.name)
        if not client:
            return None
        return client.parse_message(body)

    def post_message(self, message: Notification, **kwargs) -> None:
        for conf in self.get_configs().values():
            if not self.check_message(message, conf.name):
                continue
            userid, chat_id, receive_id_type = self._resolve_message_target(message)
            client: Feishu = self.get_instance(conf.name)
            if client:
                client.send_notification(
                    message=message,
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )

    def post_medias_message(self, message: Notification, medias: List[MediaInfo]) -> None:
        for conf in self.get_configs().values():
            if not self.check_message(message, conf.name):
                continue
            userid, chat_id, receive_id_type = self._resolve_message_target(message)
            client: Feishu = self.get_instance(conf.name)
            if client:
                client.send_medias_message(
                    message=message,
                    medias=medias,
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )

    def post_torrents_message(self, message: Notification, torrents: List[Context]) -> None:
        for conf in self.get_configs().values():
            if not self.check_message(message, conf.name):
                continue
            userid, chat_id, receive_id_type = self._resolve_message_target(message)
            client: Feishu = self.get_instance(conf.name)
            if client:
                client.send_torrents_message(
                    message=message,
                    torrents=torrents,
                    userid=userid,
                    chat_id=chat_id,
                    receive_id_type=receive_id_type,
                )

    def edit_message(
            self,
            channel: MessageChannel,
            source: str,
            message_id: Union[str, int],
            chat_id: Union[str, int],
            text: str,
            title: Optional[str] = None,
            buttons: Optional[List[List[dict]]] = None,
    ) -> bool:
        if channel != self._channel:
            return False
        for conf in self.get_configs().values():
            if source != conf.name:
                continue
            client: Feishu = self.get_instance(conf.name)
            if client and client.edit_message(
                    message_id=str(message_id),
                    title=title,
                    text=text,
                    buttons=buttons,
            ):
                return True
        return False

    def send_direct_message(self, message: Notification) -> Optional[MessageResponse]:
        for conf in self.get_configs().values():
            if not self.check_message(message, conf.name):
                continue
            userid, chat_id, receive_id_type = self._resolve_message_target(message)
            client: Feishu = self.get_instance(conf.name)
            if not client:
                continue
            result = client.send_notification(
                message=message,
                userid=userid,
                chat_id=chat_id,
                receive_id_type=receive_id_type,
            )
            if result and result.get("success"):
                return MessageResponse(
                    message_id=result.get("message_id"),
                    chat_id=result.get("chat_id"),
                    channel=MessageChannel.Feishu,
                    source=conf.name,
                    success=True,
                )
        return None
