# -*- coding: utf-8 -*-
"""
下载器（Downloader 域）一等开放注册回归：

  1. verify_downloader_contract 对合法下载器（_ModuleBase + get_type=Downloader +
     download/list_torrents/remove_torrents）通过；
  2. 对错误 ModuleType / 缺下载器方法 / 非模块类 判定失败并给出原因；
  3. 合法下载器经 register_module 严格验证后正常注册；
  4. get_plugin_provided_downloaders 聚合器按 owner 归集插件声明的下载器。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_metadata import get_plugin_provided_downloaders
from app.modules import _ModuleBase
from app.schemas.types import ModuleType


class _DownloaderOps(_ModuleBase):
    """实现 _ModuleBase 契约 + 下载器核心操作的基类。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    def download(self, *args, **kwargs):
        return None

    def list_torrents(self, *args, **kwargs):
        return []

    def remove_torrents(self, *args, **kwargs):
        return True


class _ValidDownloader(_DownloaderOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader


class _WrongTypeDownloader(_DownloaderOps):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaRecognize  # 非 Downloader


class _MissingMethodDownloader(_ModuleBase):
    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    def download(self, *args, **kwargs):
        return None

    def list_torrents(self, *args, **kwargs):
        return []

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader
    # 故意缺 remove_torrents


class TestVerifyDownloaderContract(TestCase):
    def test_valid_downloader_passes(self):
        ok, reasons = ModuleManager.verify_downloader_contract(_ValidDownloader)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])

    def test_wrong_module_type_rejected(self):
        ok, reasons = ModuleManager.verify_downloader_contract(_WrongTypeDownloader)
        self.assertFalse(ok)
        self.assertTrue(any("Downloader" in r for r in reasons))

    def test_missing_method_rejected(self):
        ok, reasons = ModuleManager.verify_downloader_contract(_MissingMethodDownloader)
        self.assertFalse(ok)
        self.assertTrue(any("remove_torrents" in r for r in reasons))

    def test_non_module_rejected(self):
        ok, reasons = ModuleManager.verify_downloader_contract(str)
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestDownloaderRegistration(TestCase):
    def setUp(self):
        self.mgr = ModuleManager()
        self.owner = "test_dl_owner"

    def tearDown(self):
        self.mgr.unregister_modules(self.owner)

    def test_valid_downloader_registers(self):
        accepted = self.mgr.register_module(_ValidDownloader, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_ValidDownloader.__name__, self.mgr.get_external_module_ids(self.owner))


class TestDownloaderAggregator(TestCase):
    def test_aggregator_collects_enabled_plugin_downloaders(self):
        class _FakePlugin:
            def get_state(self):
                return True

            def provides_downloaders(self):
                return [_ValidDownloader]

        result = get_plugin_provided_downloaders({"fakeplugin": _FakePlugin()})
        self.assertEqual(result, {"fakeplugin": [_ValidDownloader]})

    def test_aggregator_skips_disabled_plugin(self):
        class _DisabledPlugin:
            def get_state(self):
                return False

            def provides_downloaders(self):
                return [_ValidDownloader]

        result = get_plugin_provided_downloaders({"off": _DisabledPlugin()})
        self.assertEqual(result, {})
