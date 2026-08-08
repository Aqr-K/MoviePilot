# -*- coding: utf-8 -*-
"""
消息渠道（Notification 域）一等开放注册回归：

  1. verify_notification_contract 对合法消息渠道（_ModuleBase + get_type=Notification +
     post_message）通过；
  2. 对错误 ModuleType / 缺 post_message / 非模块类 判定失败并给出原因；
  3. 合法消息渠道经 register_module 严格验证后正常注册；
  4. get_plugin_provided_notifications 聚合器按 owner 归集插件声明的消息渠道，
     并跳过未启用插件。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_metadata import get_plugin_provided_notifications
from app.modules import _ModuleBase
from app.schemas.types import ModuleType


class _NotificationOps(_ModuleBase):
    """实现 _ModuleBase 契约 + 消息渠道核心方法的基类。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    def post_message(self, *args, **kwargs):
        return None


class _ValidNotification(_NotificationOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Notification


class _WrongTypeNotification(_NotificationOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaRecognize  # 非 Notification


class _MissingMethodNotification(_ModuleBase):
    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Notification
    # 故意缺 post_message


class TestVerifyNotificationContract(TestCase):
    def test_valid_notification_passes(self):
        ok, reasons = ModuleManager.verify_notification_contract(_ValidNotification)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])

    def test_wrong_module_type_rejected(self):
        ok, reasons = ModuleManager.verify_notification_contract(_WrongTypeNotification)
        self.assertFalse(ok)
        self.assertTrue(any("Notification" in r for r in reasons))

    def test_missing_method_rejected(self):
        ok, reasons = ModuleManager.verify_notification_contract(_MissingMethodNotification)
        self.assertFalse(ok)
        self.assertTrue(any("post_message" in r for r in reasons))

    def test_non_module_rejected(self):
        ok, reasons = ModuleManager.verify_notification_contract(str)
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestNotificationRegistration(TestCase):
    def setUp(self):
        self.mgr = ModuleManager()
        self.owner = "test_nf_owner"

    def tearDown(self):
        self.mgr.unregister_modules(self.owner)

    def test_valid_notification_registers(self):
        accepted = self.mgr.register_module(_ValidNotification, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_ValidNotification.__name__, self.mgr.get_external_module_ids(self.owner))


class TestNotificationAggregator(TestCase):
    def test_aggregator_collects_enabled_plugin_notifications(self):
        class _FakePlugin:
            def get_state(self):
                return True

            def provides_notifications(self):
                return [_ValidNotification]

        result = get_plugin_provided_notifications({"fakeplugin": _FakePlugin()})
        self.assertEqual(result, {"fakeplugin": [_ValidNotification]})

    def test_aggregator_skips_disabled_plugin(self):
        class _DisabledPlugin:
            def get_state(self):
                return False

            def provides_notifications(self):
                return [_ValidNotification]

        result = get_plugin_provided_notifications({"off": _DisabledPlugin()})
        self.assertEqual(result, {})
