"""P1 PR-E 单测：post_message / async_post_message 消息隔离隐私泄漏。

隔离设置为 "user" 但通知无用户上下文（username 为空，典型为系统级通知）时，
旧逻辑落入 else 分支置 send_orignal=True 并 break，导致仅特定对象可见的通知
被按原消息广播到全部公开渠道。修复后应跳过 user 动作、不广播。
"""
import sys
import asyncio
import unittest
from types import ModuleType
from unittest.mock import patch

sys.modules.setdefault("qbittorrentapi", ModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", ModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)
sys.modules.setdefault("psutil", ModuleType("psutil"))

from app.chain.message import MessageChain
from app.core.config import settings
from app.schemas import Notification
from app.schemas.types import NotificationType


class TestPostMessageIsolationLeak(unittest.TestCase):

    @staticmethod
    def _message() -> Notification:
        # 无 userid、无 username、带 mtype —— 触发按 mtype 的隔离分支
        return Notification(
            userid=None,
            username=None,
            mtype=NotificationType.Manual,
            title="仅特定对象可见",
            text="敏感内容",
        )

    @staticmethod
    def _get_settings_stub(admin_targets, user_targets=None):
        # get_settings(SUPERUSER) 返回 admin_targets（None 表示超管行不存在）；其余返回 user_targets
        def _stub(name):
            return list(admin_targets) if (name == settings.SUPERUSER and admin_targets is not None) else user_targets
        return _stub

    def _run_sync(self, chain, message, switch, admin_targets=("admin_target",), user_targets=None):
        with patch("app.chain.MessageTemplateHelper.render", return_value=message), \
                patch.object(chain.messagehelper, "put"), \
                patch.object(chain.messageoper, "add"), \
                patch("app.chain.ServiceConfigHelper.get_notification_switch", return_value=switch), \
                patch("app.chain.UserOper") as user_oper_cls, \
                patch.object(chain.eventmanager, "send_event"), \
                patch.object(chain.messagequeue, "send_message") as send_message:
            user_oper_cls.return_value.get_settings.side_effect = self._get_settings_stub(admin_targets, user_targets)
            chain.post_message(message)
        return send_message

    def _run_async(self, chain, message, switch, admin_targets=("admin_target",), user_targets=None):
        with patch("app.chain.MessageTemplateHelper.render", return_value=message), \
                patch.object(chain.messagehelper, "put"), \
                patch.object(chain.messageoper, "add"), \
                patch("app.chain.ServiceConfigHelper.get_notification_switch", return_value=switch), \
                patch("app.chain.UserOper") as user_oper_cls, \
                patch.object(chain.eventmanager, "async_send_event"), \
                patch.object(chain.messagequeue, "async_send_message") as async_send:
            user_oper_cls.return_value.get_settings.side_effect = self._get_settings_stub(admin_targets, user_targets)
            asyncio.run(chain.async_post_message(message))
        return async_send

    # ---- 隐私泄漏核心用例 ----

    def test_user_isolation_without_username_does_not_broadcast(self):
        send_message = self._run_sync(MessageChain(), self._message(), "user")
        send_message.assert_not_called()

    def test_async_user_isolation_without_username_does_not_broadcast(self):
        async_send = self._run_async(MessageChain(), self._message(), "user")
        async_send.assert_not_called()

    # ---- 修复不得误伤 admin 投递 ----

    def test_user_admin_isolation_without_username_sends_admin_only(self):
        send_message = self._run_sync(MessageChain(), self._message(), "user,admin")
        self.assertEqual(send_message.call_count, 1)
        sent = send_message.call_args.kwargs["message"]
        self.assertEqual(sent.targets, ["admin_target"])

    # ---- 修复不得破坏 "all" 广播（回归守卫）----

    def test_all_isolation_still_broadcasts(self):
        send_message = self._run_sync(MessageChain(), self._message(), "all")
        send_message.assert_called()

    # ---- 审查发现 #1：admin 目标不存在时不得按无目标广播 ----

    def test_admin_isolation_missing_superuser_does_not_broadcast(self):
        # 超管行被改名/删除/env 变更 → get_settings(SUPERUSER)=None，不应下发（否则下游 telegram 默认群 / wechat @all 广播）
        send_message = self._run_sync(MessageChain(), self._message(), "admin", admin_targets=None)
        send_message.assert_not_called()

    def test_async_admin_isolation_missing_superuser_does_not_broadcast(self):
        async_send = self._run_async(MessageChain(), self._message(), "admin", admin_targets=None)
        async_send.assert_not_called()

    def test_user_not_found_rollback_missing_superuser_does_not_broadcast(self):
        # user 找不到回滚到 admin，但 admin 也不存在 → 不应广播
        msg = Notification(userid=None, username="ghost", mtype=NotificationType.Manual, title="t", text="x")
        send_message = self._run_sync(MessageChain(), msg, "user", admin_targets=None, user_targets=None)
        send_message.assert_not_called()

    # ---- 审查发现 #2/#3：else fail-open + token 空白/大小写 ----

    def test_user_admin_with_whitespace_sends_admin_only(self):
        # "user, admin"（逗号后带空格）经 API 直写可达；规范化后应只发管理员、绝不广播
        send_message = self._run_sync(MessageChain(), self._message(), "user, admin")
        self.assertEqual(send_message.call_count, 1)
        self.assertEqual(send_message.call_args.kwargs["message"].targets, ["admin_target"])

    def test_unknown_action_does_not_broadcast(self):
        # 未知/拼写错误 token（自由字符串，无枚举校验）应 fail-closed，不广播
        send_message = self._run_sync(MessageChain(), self._message(), "usr")
        send_message.assert_not_called()

    def test_uppercase_admin_token_sends_admin_only(self):
        # 大小写变体应规范化匹配 admin
        send_message = self._run_sync(MessageChain(), self._message(), "ADMIN")
        self.assertEqual(send_message.call_count, 1)
        self.assertEqual(send_message.call_args.kwargs["message"].targets, ["admin_target"])
