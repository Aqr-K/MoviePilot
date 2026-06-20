# -*- coding: utf-8 -*-
"""
Q1-S2 回归测试：子类型字符串化（get_subtype_id + get_running_subtype_module 字符串相等）。

验证：
  1. _ModuleBase.get_subtype_id() 默认实现 == get_subtype().value（内建模块零改动获得字符串标识）；
  2. get_subtype() 返回 None 时 get_subtype_id() 返回 ""（兜底不崩）；
  3. get_running_subtype_module 既能用 Enum 查询、也能用等价字符串查询命中（向后兼容）；
  4. 插件可仅重写 get_subtype_id() 返回封闭枚举外的纯字符串（如 "aria2"），被字符串查询命中。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.modules import _ModuleBase
from app.schemas.types import ModuleType, DownloaderType


class _EnumSubModule(_ModuleBase):
    """子类型用内建 Enum，不重写 get_subtype_id（走默认 .value）"""

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
        return ModuleType.Downloader

    @staticmethod
    def get_subtype() -> DownloaderType:
        return DownloaderType.Transmission

    @staticmethod
    def get_priority() -> int:
        return 99

    def download(self, *args, **kwargs):
        return "enum-sub"


class _StrSubModule(_ModuleBase):
    """插件式：重写 get_subtype_id 返回封闭枚举外的纯字符串 'aria2'"""

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
        return ModuleType.Downloader

    def get_subtype_id(self) -> str:
        return "aria2"

    @staticmethod
    def get_priority() -> int:
        return 99

    def download(self, *args, **kwargs):
        return "str-sub"


class _NoneSubModule(_ModuleBase):
    """get_subtype 返回 None（默认），验证 get_subtype_id 兜底返回 ''"""

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
        return ModuleType.Other


_OWNER = "test.plugin.q1s2"


class ModuleSubtypeIdTest(TestCase):

    def setUp(self):
        self.mm = ModuleManager()

    def tearDown(self):
        self.mm.unregister_modules(_OWNER)

    def test_default_subtype_id_equals_enum_value(self):
        self.assertEqual(_EnumSubModule().get_subtype_id(), DownloaderType.Transmission.value)
        self.assertEqual(_EnumSubModule().get_subtype_id(), "Transmission")

    def test_none_subtype_id_is_empty(self):
        self.assertEqual(_NoneSubModule().get_subtype_id(), "")

    def test_enum_and_string_query_equivalent(self):
        self.mm.register_module(_EnumSubModule, owner=_OWNER)
        by_enum = [type(m) for m in self.mm.get_running_subtype_module(DownloaderType.Transmission)]
        by_str = [type(m) for m in self.mm.get_running_subtype_module("Transmission")]
        self.assertIn(_EnumSubModule, by_enum)
        self.assertIn(_EnumSubModule, by_str)

    def test_plugin_string_subtype_dispatch(self):
        self.mm.register_module(_StrSubModule, owner=_OWNER)
        by_str = [type(m) for m in self.mm.get_running_subtype_module("aria2")]
        self.assertIn(_StrSubModule, by_str)
        # 不会被无关子类型查询误命中
        by_other = [type(m) for m in self.mm.get_running_subtype_module(DownloaderType.Transmission)]
        self.assertNotIn(_StrSubModule, by_other)
