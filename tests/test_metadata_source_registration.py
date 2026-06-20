# -*- coding: utf-8 -*-
"""
元数据数据源（Metadata / MediaRecognize 域）开放注册「已覆盖」回归。

结论性测试：元数据数据源已由既有 provides_data_sources(#61) 一等开放注册，本域无需新增结构。
本测试把该事实钉死、可执行：

  1. 内建识别型元数据源（TheMovieDb / Douban / Bangumi）均声明 get_type()==MediaRecognize；
  2. 均通过 verify_data_source_contract（即插件可经 provides_data_sources 同等注册新元数据源）；
  3. provides_data_sources 钩子 + get_plugin_provided_data_sources 聚合器机制已就位。

边界事实：FanartModule 是 get_type()==Other 的【图片提供方】（非识别源），按设计走通用
provides_modules() 而不归 provides_data_sources（后者严格要求 MediaRecognize），仍经 run_module
按方法名参与 obtain_images 分发——故本域开放注册对象是三个 MediaRecognize 源，与 Fanart 解耦。

注：推荐/发现方法（tmdb_discover 等）就挂在这些 MediaRecognize 模块上，模块级随本域注册即可
参与分发；其 UI 源枚举的声明式注册见 test_discover_recommend_registration.py。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_metadata import get_plugin_provided_data_sources
from app.modules import _ModuleBase
from app.plugins import _PluginBase
from app.schemas.types import ModuleType


def _builtin_metadata_modules():
    from app.modules.themoviedb import TheMovieDbModule
    from app.modules.douban import DoubanModule
    from app.modules.bangumi import BangumiModule
    return [TheMovieDbModule, DoubanModule, BangumiModule]


class _PluginMetaSource(_ModuleBase):
    """模拟插件经 provides_data_sources 新增的元数据源（MediaRecognize）。"""

    def init_module(self):
        pass

    def init_setting(self):
        return None

    def stop(self):
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_type():
        return ModuleType.MediaRecognize


class TestBuiltinMetadataSourcesAreFirstClass(TestCase):
    def test_all_builtins_declare_mediarecognize_type(self):
        for cls in _builtin_metadata_modules():
            self.assertEqual(cls.get_type(), ModuleType.MediaRecognize,
                             f"{cls.__name__} 应声明 get_type()==MediaRecognize")

    def test_all_builtins_pass_data_source_contract(self):
        for cls in _builtin_metadata_modules():
            ok, reasons = ModuleManager.verify_data_source_contract(cls)
            self.assertTrue(ok, f"{cls.__name__} 未通过数据源契约：{reasons}")

    def test_fanart_is_other_typed_image_provider(self):
        # 边界：Fanart 是 Other（图片源），不归 provides_data_sources 的 MediaRecognize 契约
        from app.modules.fanart import FanartModule
        self.assertEqual(FanartModule.get_type(), ModuleType.Other)
        ok, _ = ModuleManager.verify_data_source_contract(FanartModule)
        self.assertFalse(ok)


class TestMetadataOpenRegistrationMechanismPresent(TestCase):
    def test_provides_data_sources_hook_exists(self):
        # _PluginBase 默认提供 provides_data_sources 钩子，插件覆写即注册新元数据源
        self.assertTrue(callable(getattr(_PluginBase, "provides_data_sources", None)))

    def test_aggregator_collects_plugin_metadata_sources(self):
        class _FakePlugin:
            def get_state(self):
                return True

            def provides_data_sources(self):
                return [_PluginMetaSource]

        result = get_plugin_provided_data_sources({"meta_plugin": _FakePlugin()})
        self.assertEqual(result, {"meta_plugin": [_PluginMetaSource]})
        # 且该插件源能通过数据源契约
        ok, reasons = ModuleManager.verify_data_source_contract(_PluginMetaSource)
        self.assertTrue(ok, reasons)
