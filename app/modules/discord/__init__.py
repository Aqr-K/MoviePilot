from typing import Optional, Union, List, Tuple, Any

from app.core.context import MediaInfo, Context
from app.log import logger
from app.modules import _ModuleBase, _MessageBase
from app.modules.discord.discord import Discord
from app.schemas import MessageChannel, CommingMessage, Notification
from app.schemas.types import ModuleType


class DiscordModule(_ModuleBase, _MessageBase[Discord]):

    def init_module(self) -> None:
        """
        初始化模块
        """
        super().init_service(service_name=Discord.__name__.lower(),
                             service_type=Discord)
        self._channel = MessageChannel.Discord

    @staticmethod
    def get_name() -> str:
        return "Discord"

    @staticmethod
    def get_type() -> ModuleType:
        """
        获取模块类型
        """
        return ModuleType.Notification

    @staticmethod
    def get_subtype() -> MessageChannel:
        """
        获取模块子类型
        """
        return MessageChannel.Discord

    @staticmethod
    def get_priority() -> int:
        """
        获取模块优先级，数字越小优先级越高，只有同一接口下优先级才生效
        """
        return 4

    def stop(self):
        """
        停止模块
        """
        for client in self.get_instances().values():
            client.stop()

    def test(self) -> Optional[Tuple[bool, str]]:
        """
        测试模块连接性
        """
        if not self.get_instances():
            return None
        for name, client in self.get_instances().items():
            state = client.get_state()
            if not state:
                return False, f"Discord {name} webhook URL 未配置"
        return True, ""

    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        pass

    def message_parser(self, source: str, body: Any, form: Any, args: Any) -> Optional[CommingMessage]:
        """
        解析消息内容，返回字典，注意以下约定值：
        userid: 用户ID
        username: 用户名
        text: 内容
        :param source: 消息来源
        :param body: 请求体
        :param form: 表单
        :param args: 参数
        :return: 渠道、消息体
        """
        # Discord 模块暂时不支持接收消息
        
        return None

    def post_message(self, message: Notification, **kwargs) -> None:
        """
        发送通知消息
        :param message: 消息通知对象
        """
        for conf in self.get_configs().values():
            if not self.check_message(message, conf.name):
                continue
            client: Discord = self.get_instance(conf.name)
            if client:
                client.send_msg(title=message.title, text=message.text,
                                image=message.image, userid=message.userid, link=message.link,
                                buttons=message.buttons,
                                original_message_id=message.original_message_id,
                                original_chat_id=message.original_chat_id)

    def post_medias_message(self, message: Notification, medias: List[MediaInfo]) -> None:
        """
        发送媒体信息选择列表
        :param message: 消息体
        :param medias: 媒体信息
        :return: 成功或失败
        """
        logger.warn("Discord webhooks 不支持")
        return None

    def post_torrents_message(self, message: Notification, torrents: List[Context]) -> None:
        """
        发送种子信息选择列表
        :param message: 消息体
        :param torrents: 种子信息
        :return: 成功或失败
        """
        logger.warn("Discord webhooks 不支持")
        return False

    def delete_message(self, channel: MessageChannel, source: str,
                       message_id: str, chat_id: Optional[str] = None) -> bool:
        """
        删除消息
        :param channel: 消息渠道
        :param source: 指定的消息源
        :param message_id: 消息ID（Slack中为时间戳）
        :param chat_id: 聊天ID（频道ID）
        :return: 删除是否成功
        """
        logger.warn("Discord webhooks 不支持")
        return False
