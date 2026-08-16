"""消息通知渠道。

每个通知渠道是一个独立模块，以渠道类型作为模块子类型。
模块扫描只遍历 ``app.modules`` 的一级条目，具体渠道类须在此处导出才能进入注册表。
"""
from app.modules.notifications.discord import DiscordModule
from app.modules.notifications.feishu import FeishuModule
from app.modules.notifications.qqbot import QQBotModule
from app.modules.notifications.slack import SlackModule
from app.modules.notifications.synologychat import SynologyChatModule
from app.modules.notifications.telegram import TelegramModule
from app.modules.notifications.vocechat import VoceChatModule
from app.modules.notifications.webpush import WebPushModule
from app.modules.notifications.wechat import WechatModule
from app.modules.notifications.wechatclawbot import WechatClawBotModule

__all__ = [
    "DiscordModule",
    "FeishuModule",
    "QQBotModule",
    "SlackModule",
    "SynologyChatModule",
    "TelegramModule",
    "VoceChatModule",
    "WebPushModule",
    "WechatModule",
    "WechatClawBotModule",
]
