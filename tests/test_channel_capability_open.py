# -*- coding: utf-8 -*-
"""
Q1-S6 回归测试：ChannelCapabilityManager 消息渠道能力矩阵开放注册。

验证：
  1. register_capabilities(channel, caps, owner) 后，get_capabilities/supports_* 能查到插件渠道
     （按字符串 channel id 容错匹配，无需扩展封闭 MessageChannel 枚举）；
  2. unregister_capabilities(owner) 后插件渠道能力下线；
  3. 内建渠道（如 Telegram）能力不受影响；
  4. PluginManager._register/_unregister_plugin_modules 接通 provides_channel_capabilities。
"""
from unittest import TestCase

from app.helper.plugin_manager import PluginManager
from app.schemas.message import (
    ChannelCapabilityManager,
    ChannelCapabilities,
    ChannelCapability,
)
from app.schemas.types import MessageChannel


_OWNER = "test.plugin.q1s6"
_CHANNEL = "mychannel"


def _make_caps():
    return ChannelCapabilities(
        channel=_CHANNEL,
        capabilities={ChannelCapability.INLINE_BUTTONS, ChannelCapability.MARKDOWN},
        max_buttons_per_row=3,
    )


class _FakeChannelPlugin:
    def __init__(self, caps):
        self._caps = caps

    def get_state(self) -> bool:
        return True

    def get_name(self) -> str:
        return "FakeChannelPlugin"

    def provides_modules(self):
        return []

    def provides_storages(self):
        return []

    def provides_channel_capabilities(self):
        return [self._caps]


class ChannelCapabilityOpenTest(TestCase):

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

    def test_plugin_manager_wires_capabilities(self):
        pm = PluginManager()
        saved = dict(pm._running_plugins)
        caps = _make_caps()
        try:
            pm._running_plugins = {_OWNER: _FakeChannelPlugin(caps)}
            pm._register_plugin_modules()
            self.assertIs(ChannelCapabilityManager.get_capabilities(_CHANNEL), caps)
            pm._unregister_plugin_modules([_OWNER])
            self.assertIsNone(ChannelCapabilityManager.get_capabilities(_CHANNEL))
        finally:
            pm._running_plugins = saved
            ChannelCapabilityManager.unregister_capabilities(_OWNER)
