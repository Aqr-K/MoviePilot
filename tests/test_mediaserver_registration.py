# -*- coding: utf-8 -*-
"""
媒体服务器（MediaServer 域）一等开放注册回归：

  1. verify_mediaserver_contract 对合法媒体服务器（_ModuleBase + get_type=MediaServer）通过；
  2. 对错误 ModuleType / 非模块类 判定失败并给出原因；
  3. 合法媒体服务器经 register_module 严格验证后正常注册；
  4. get_plugin_provided_mediaservers 聚合器按 owner 归集插件声明的媒体服务器，
     并跳过未启用插件。

媒体服务器契约仅校验类型（不强制具体能力方法）——各后端 emby/jellyfin/plex/trimemedia/
ugreen/zspace 实现的方法子集不同，由 run_module 按方法名分发、按需实现，与数据源域一致。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_metadata import get_plugin_provided_mediaservers
from app.modules import _ModuleBase
from app.schemas.types import ModuleType


class _MediaServerOps(_ModuleBase):
    """实现 _ModuleBase 契约的媒体服务器基类（能力方法按需实现，此处给一个示例方法）。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    def mediaserver_librarys(self, *args, **kwargs):
        return []


class _ValidMediaServer(_MediaServerOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaServer


class _WrongTypeMediaServer(_MediaServerOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader  # 非 MediaServer


class _NoMethodMediaServer(_ModuleBase):
    """仅声明类型、不实现任何能力方法——类型契约下应仍通过（方法按需分发）。"""

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
        return ModuleType.MediaServer


class TestVerifyMediaServerContract(TestCase):
    def test_valid_mediaserver_passes(self):
        ok, reasons = ModuleManager.verify_mediaserver_contract(_ValidMediaServer)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])

    def test_type_only_contract_allows_no_capability_methods(self):
        # 仅类型契约：不实现具体能力方法也应通过（与数据源域一致）
        ok, reasons = ModuleManager.verify_mediaserver_contract(_NoMethodMediaServer)
        self.assertTrue(ok, reasons)

    def test_wrong_module_type_rejected(self):
        ok, reasons = ModuleManager.verify_mediaserver_contract(_WrongTypeMediaServer)
        self.assertFalse(ok)
        self.assertTrue(any("MediaServer" in r for r in reasons))

    def test_non_module_rejected(self):
        ok, reasons = ModuleManager.verify_mediaserver_contract(str)
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestMediaServerRegistration(TestCase):
    def setUp(self):
        self.mgr = ModuleManager()
        self.owner = "test_ms_owner"

    def tearDown(self):
        self.mgr.unregister_modules(self.owner)

    def test_valid_mediaserver_registers(self):
        accepted = self.mgr.register_module(_ValidMediaServer, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_ValidMediaServer.__name__, self.mgr.get_external_module_ids(self.owner))


class TestMediaServerAggregator(TestCase):
    def test_aggregator_collects_enabled_plugin_mediaservers(self):
        class _FakePlugin:
            def get_state(self):
                return True

            def provides_mediaservers(self):
                return [_ValidMediaServer]

        result = get_plugin_provided_mediaservers({"fakeplugin": _FakePlugin()})
        self.assertEqual(result, {"fakeplugin": [_ValidMediaServer]})

    def test_aggregator_skips_disabled_plugin(self):
        class _DisabledPlugin:
            def get_state(self):
                return False

            def provides_mediaservers(self):
                return [_ValidMediaServer]

        result = get_plugin_provided_mediaservers({"off": _DisabledPlugin()})
        self.assertEqual(result, {})
