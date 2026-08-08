# -*- coding: utf-8 -*-
"""
消息渠道能力矩阵开放注册回归。

验证：
  1. register_capabilities(channel, caps, owner) 后，get_capabilities/supports_* 能查到插件渠道
     （按字符串 channel id 容错匹配，无需扩展封闭 MessageChannel 枚举）；
  2. unregister_capabilities(owner) 后插件渠道能力下线；
  3. 内建渠道（如 Telegram）能力不受影响；
  4. 能力声明收口进渠道模块：PluginManager 注册 provides_notifications 渠道模块时，自动读取其
     get_channel_capabilities() 能力矩阵并登记，channel id 取自模块 get_subtype_id()（一处声明）；
     卸载插件时能力一并下线；未声明能力的渠道模块走降级默认。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_manager import PluginManager
from app.modules import _ModuleBase
from app.schemas.message import (
    ChannelCapabilityManager,
    ChannelCapabilities,
    ChannelCapability,
)
from app.schemas.types import MessageChannel, ModuleType


_OWNER = "test.plugin.q1s6"
_CHANNEL = "mychannel"


def _make_caps(channel=_CHANNEL):
    return ChannelCapabilities(
        channel=channel,
        capabilities={ChannelCapability.INLINE_BUTTONS, ChannelCapability.MARKDOWN},
        max_buttons_per_row=3,
    )


class _ChannelModuleBase(_ModuleBase):
    """实现 _ModuleBase 契约 + 消息渠道核心方法的测试用渠道模块基类。"""

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

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Notification


class _CapableChannel(_ChannelModuleBase):
    """自带能力声明的插件渠道模块：get_subtype_id() 即唯一 channel id 声明处。"""

    def get_subtype_id(self) -> str:
        return _CHANNEL

    def get_channel_capabilities(self):
        return _make_caps(channel=_CHANNEL)


class _MislabeledChannel(_ChannelModuleBase):
    """能力声明里 channel 字段填错的渠道模块：框架应以 get_subtype_id() 为准登记。"""

    def get_subtype_id(self) -> str:
        return "rightchannel"

    def get_channel_capabilities(self):
        return _make_caps(channel="WRONGCHANNEL")


class _PlainChannel(_ChannelModuleBase):
    """不声明能力的插件渠道模块：注册成功，能力走降级默认。"""

    def get_subtype_id(self) -> str:
        return "plainchannel"


class _FakeChannelPlugin:
    def __init__(self, module_cls):
        self._module_cls = module_cls

    def get_state(self) -> bool:
        return True

    def get_name(self) -> str:
        return "FakeChannelPlugin"

    def provides_notifications(self):
        return [self._module_cls]


class ChannelCapabilityManagerTest(TestCase):
    """直连 ChannelCapabilityManager API 的回归（与插件注册路径无关）。"""

    def tearDown(self):
        ChannelCapabilityManager.unregister_capabilities(_OWNER)

    def test_register_and_lookup(self):
        caps = _make_caps()
        ok = ChannelCapabilityManager.register_capabilities(_CHANNEL, caps, owner=_OWNER)
        self.assertTrue(ok)
        self.assertIs(ChannelCapabilityManager.get_capabilities(_CHANNEL), caps)
        self.assertTrue(ChannelCapabilityManager.supports_buttons(_CHANNEL))
        self.assertTrue(ChannelCapabilityManager.supports_markdown(_CHANNEL))
        self.assertEqual(ChannelCapabilityManager.get_max_buttons_per_row(_CHANNEL), 3)

    def test_unregister(self):
        ChannelCapabilityManager.register_capabilities(_CHANNEL, _make_caps(), owner=_OWNER)
        ChannelCapabilityManager.unregister_capabilities(_OWNER)
        self.assertIsNone(ChannelCapabilityManager.get_capabilities(_CHANNEL))
        # 未注册渠道走降级默认
        self.assertFalse(ChannelCapabilityManager.supports_buttons(_CHANNEL))

    def test_builtin_channel_unaffected(self):
        before = ChannelCapabilityManager.get_capabilities(MessageChannel.Telegram)
        self.assertIsNotNone(before)
        self.assertTrue(ChannelCapabilityManager.supports_buttons(MessageChannel.Telegram))
        ChannelCapabilityManager.register_capabilities(_CHANNEL, _make_caps(), owner=_OWNER)
        self.assertIs(ChannelCapabilityManager.get_capabilities(MessageChannel.Telegram), before)
        self.assertTrue(ChannelCapabilityManager.supports_buttons(MessageChannel.Telegram))


class ChannelCapabilityWiringTest(TestCase):
    """能力声明收口进渠道模块：经 PluginManager 注册路径接通。"""

    def _run_with_plugin(self, module_cls):
        pm = PluginManager()
        saved = dict(pm._running_plugins)
        pm._running_plugins = {_OWNER: _FakeChannelPlugin(module_cls)}
        try:
            pm._register_plugin_modules()
        finally:
            pm._running_plugins = saved
        return pm

    def _cleanup(self):
        ChannelCapabilityManager.unregister_capabilities(_OWNER)
        ModuleManager().unregister_modules(_OWNER)

    def tearDown(self):
        self._cleanup()

    def test_capabilities_registered_from_module(self):
        self._run_with_plugin(_CapableChannel)
        self.assertIsNotNone(ChannelCapabilityManager.get_capabilities(_CHANNEL))
        self.assertTrue(ChannelCapabilityManager.supports_buttons(_CHANNEL))
        self.assertTrue(ChannelCapabilityManager.supports_markdown(_CHANNEL))
        self.assertEqual(ChannelCapabilityManager.get_max_buttons_per_row(_CHANNEL), 3)

    def test_channel_id_taken_from_module_subtype(self):
        # 能力声明里 channel="WRONGCHANNEL"，但框架以 get_subtype_id()="rightchannel" 登记
        self._run_with_plugin(_MislabeledChannel)
        self.assertIsNotNone(ChannelCapabilityManager.get_capabilities("rightchannel"))
        self.assertTrue(ChannelCapabilityManager.supports_buttons("rightchannel"))
        self.assertIsNone(ChannelCapabilityManager.get_capabilities("WRONGCHANNEL"))

    def test_unregister_removes_capabilities(self):
        pm = self._run_with_plugin(_CapableChannel)
        self.assertIsNotNone(ChannelCapabilityManager.get_capabilities(_CHANNEL))
        pm._unregister_plugin_modules([_OWNER])
        self.assertIsNone(ChannelCapabilityManager.get_capabilities(_CHANNEL))

    def test_notification_without_capabilities_falls_back(self):
        self._run_with_plugin(_PlainChannel)
        # 渠道模块本身已注册进 ModuleManager
        self.assertIn(_PlainChannel.__name__, ModuleManager().get_external_module_ids(_OWNER))
        # 未声明能力 → 走降级默认（不支持按钮）
        self.assertIsNone(ChannelCapabilityManager.get_capabilities("plainchannel"))
        self.assertFalse(ChannelCapabilityManager.supports_buttons("plainchannel"))
