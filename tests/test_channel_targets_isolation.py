"""渠道级隔离契约单测：隔离消息（无 userid 但带 targets）在无法解析出本渠道目标时，
各渠道 post_message 必须 fail-closed（不发送 / 不广播），绝不回退默认群或全量广播。

覆盖对抗审查（PR #99）发现的 4 个漏网渠道：vocechat / webpush / feishu / qqbot。
对照合规基线 telegram/wechat：if not userid and targets is not None: ...; if not userid: return。
"""
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

sys.modules.setdefault("qbittorrentapi", ModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", ModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)

from app.modules.vocechat import VoceChatModule
from app.modules.webpush import WebPushModule
from app.modules.feishu import FeishuModule
from app.modules.qqbot import QQBotModule
from app.schemas import Notification
from app.schemas.types import NotificationType

# 隔离消息：无 userid、targets 只含“别的渠道”的键（模拟管理员只绑定了 telegram）
FOREIGN_TARGETS = {"telegram_userid": "tg1"}


def _isolated(targets=None):
    return Notification(userid=None, username=None, mtype=NotificationType.Manual,
                        title="仅特定对象可见", text="敏感内容", targets=targets)


def _bare(cls):
    return cls.__new__(cls)


def _patch_dispatch(mod, client=None):
    conf = SimpleNamespace(name="default", config={})
    return (
        patch.object(mod, "get_configs", return_value={"default": conf}),
        patch.object(mod, "check_message", return_value=True),
        patch.object(mod, "get_instance", return_value=client if client is not None else MagicMock()),
    )


class TestChannelTargetsIsolation(unittest.TestCase):

    # ---- vocechat ----
    def test_vocechat_isolated_foreign_target_not_sent(self):
        mod = _bare(VoceChatModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated(FOREIGN_TARGETS))
        client.send_msg.assert_not_called()

    def test_vocechat_isolated_own_target_sent(self):
        mod = _bare(VoceChatModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated({"vocechat_userid": "vc1"}))
        client.send_msg.assert_called_once()
        self.assertEqual(client.send_msg.call_args.kwargs.get("userid"), "vc1")

    # ---- qqbot ----
    def test_qqbot_isolated_foreign_target_not_sent(self):
        mod = _bare(QQBotModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated(FOREIGN_TARGETS))
        client.send_msg.assert_not_called()

    def test_qqbot_isolated_own_target_sent(self):
        mod = _bare(QQBotModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated({"qq_userid": "q1"}))
        client.send_msg.assert_called_once()

    # ---- feishu ----
    def test_feishu_isolated_foreign_target_not_sent(self):
        mod = _bare(FeishuModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated(FOREIGN_TARGETS))
        client.send_notification.assert_not_called()

    def test_feishu_isolated_own_target_sent(self):
        mod = _bare(FeishuModule)
        client = MagicMock()
        gc, cm, gi = _patch_dispatch(mod, client)
        with gc, cm, gi:
            mod.post_message(_isolated({"feishu_openid": "f1"}))
        client.send_notification.assert_called_once()

    # ---- webpush（结构上无法定向：隔离消息一律 fail-closed，全局消息才广播）----
    def test_webpush_isolated_message_not_pushed(self):
        mod = _bare(WebPushModule)
        conf = SimpleNamespace(name="default", config={})
        with patch.object(mod, "get_configs", return_value={"default": conf}), \
                patch.object(mod, "check_message", return_value=True), \
                patch("app.modules.webpush.global_vars") as gv, \
                patch("app.modules.webpush.webpush") as push:
            gv.get_subscriptions.return_value = [{"endpoint": "e"}]
            mod.post_message(_isolated(FOREIGN_TARGETS))
        push.assert_not_called()

    def test_webpush_global_message_still_broadcasts(self):
        mod = _bare(WebPushModule)
        conf = SimpleNamespace(name="default", config={})
        with patch.object(mod, "get_configs", return_value={"default": conf}), \
                patch.object(mod, "check_message", return_value=True), \
                patch("app.modules.webpush.settings") as st, \
                patch("app.modules.webpush.global_vars") as gv, \
                patch("app.modules.webpush.webpush") as push:
            st.VAPID = {"privateKey": "k", "subject": "s"}
            gv.get_subscriptions.return_value = [{"endpoint": "e"}]
            mod.post_message(_isolated(targets=None))  # 全局消息（targets 为 None）
        push.assert_called()
