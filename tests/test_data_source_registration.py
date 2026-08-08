# -*- coding: utf-8 -*-
"""
数据源（MediaRecognize 域）一等开放注册回归：

  1. verify_data_source_contract 对合法数据源（_ModuleBase + get_type=MediaRecognize +
     recognize_media/search_medias/obtain_images）通过；
  2. 对错误 ModuleType / 缺数据源方法 / 非模块类 判定失败并给出原因；
  3. 合法数据源经 register_module 严格验证后正常注册；
  4. get_plugin_provided_data_sources 聚合器按 owner 归集插件声明的数据源。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_metadata import get_plugin_provided_data_sources
from app.modules import _ModuleBase
from app.schemas.types import ModuleType


class _MediaRecognizeBase(_ModuleBase):
    """实现 _ModuleBase 契约 + 数据源核心方法的基类。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    def recognize_media(self, *args, **kwargs):
        return None

    def search_medias(self, *args, **kwargs):
        return []

    def obtain_images(self, *args, **kwargs):
        return None


class _ValidDataSource(_MediaRecognizeBase):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaRecognize


class _WrongTypeSource(_MediaRecognizeBase):
    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader  # 非 MediaRecognize


class _MinimalSource(_ModuleBase):
    """MediaRecognize 源但不实现任何识别能力方法（如真实的 thetvdb）——契约应通过。"""

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
        return ModuleType.MediaRecognize


class TestVerifyDataSourceContract(TestCase):
    def test_valid_data_source_passes(self):
        ok, reasons = ModuleManager.verify_data_source_contract(_ValidDataSource)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])

    def test_wrong_module_type_rejected(self):
        ok, reasons = ModuleManager.verify_data_source_contract(_WrongTypeSource)
        self.assertFalse(ok)
        self.assertTrue(any("MediaRecognize" in r for r in reasons))

    def test_minimal_media_recognize_passes(self):
        # MediaRecognize 源即便未实现识别方法也应通过（识别方法按需、框架按名分发；如真实 thetvdb）
        ok, reasons = ModuleManager.verify_data_source_contract(_MinimalSource)
        self.assertTrue(ok, reasons)

    def test_non_module_rejected(self):
        ok, reasons = ModuleManager.verify_data_source_contract(str)
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestDataSourceRegistration(TestCase):
    def setUp(self):
        self.mgr = ModuleManager()
        self.owner = "test_ds_owner"

    def tearDown(self):
        self.mgr.unregister_modules(self.owner)

    def test_valid_data_source_registers(self):
        accepted = self.mgr.register_module(_ValidDataSource, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_ValidDataSource.__name__, self.mgr.get_external_module_ids(self.owner))


class TestDataSourceAggregator(TestCase):
    def test_aggregator_collects_enabled_plugin_sources(self):
        class _FakePlugin:
            def get_state(self):
                return True

            def provides_data_sources(self):
                return [_ValidDataSource]

        result = get_plugin_provided_data_sources({"fakeplugin": _FakePlugin()})
        self.assertEqual(result, {"fakeplugin": [_ValidDataSource]})

    def test_aggregator_skips_disabled_plugin(self):
        class _DisabledPlugin:
            def get_state(self):
                return False

            def provides_data_sources(self):
                return [_ValidDataSource]

        result = get_plugin_provided_data_sources({"off": _DisabledPlugin()})
        self.assertEqual(result, {})
