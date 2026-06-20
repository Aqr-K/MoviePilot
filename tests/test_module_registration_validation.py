# -*- coding: utf-8 -*-
"""
验证注册机制回归：register_module 从「注入」升级为「_ModuleBase 基类契约验证」（软废弃）。

验证：
  1. verify_module_contract 对合法 _ModuleBase 子类通过（无原因）；
  2. 对未继承 _ModuleBase / 缺契约方法 / 签名不兼容 / 非类对象 判定失败并给出原因；
  3. register_module 对不合规类发 DeprecationWarning 但仍兼容接受（软废弃，零插件破坏）；
  4. register_module 对合规类不发 DeprecationWarning。
"""
import warnings
from unittest import TestCase

from app.core.module import ModuleManager
from app.modules import _ModuleBase
from app.schemas.types import ModuleType, DownloaderType


class _ValidModule(_ModuleBase):
    """合法外部模块：继承 _ModuleBase 且实现全部契约方法。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_name() -> str:
        return "ValidStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader

    @staticmethod
    def get_subtype() -> DownloaderType:
        return DownloaderType.Qbittorrent

    @staticmethod
    def get_priority() -> int:
        return 99


class _InjectedModule:
    """旧「注入」路径：未继承 _ModuleBase，仅鸭子实现契约方法。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_type():
        return None

    @staticmethod
    def get_subtype():
        return None


class _MissingMethodModule:
    """未继承且缺 get_type 契约方法。"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_subtype():
        return None


class _BadSignatureModule(_ModuleBase):
    """契约方法要求额外必填位置参 → 签名不兼容。"""

    def init_module(self, extra) -> None:  # noqa: 故意的不兼容签名
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""


class TestVerifyModuleContract(TestCase):
    def test_valid_module_passes(self):
        ok, reasons = ModuleManager.verify_module_contract(_ValidModule)
        self.assertTrue(ok)
        self.assertEqual(reasons, [])

    def test_non_subclass_fails_with_reason(self):
        ok, reasons = ModuleManager.verify_module_contract(_InjectedModule)
        self.assertFalse(ok)
        self.assertTrue(any("未继承" in r for r in reasons))

    def test_missing_method_reported(self):
        ok, reasons = ModuleManager.verify_module_contract(_MissingMethodModule)
        self.assertFalse(ok)
        self.assertTrue(any("get_type" in r for r in reasons))

    def test_bad_signature_reported(self):
        ok, reasons = ModuleManager.verify_module_contract(_BadSignatureModule)
        self.assertFalse(ok)
        self.assertTrue(any(("init_module" in r and "签名" in r) for r in reasons))

    def test_non_type_rejected(self):
        ok, reasons = ModuleManager.verify_module_contract("not-a-class")
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestRegisterModuleSoftDeprecation(TestCase):
    def setUp(self):
        self.mgr = ModuleManager()
        self.owner = "test_validation_owner"

    def tearDown(self):
        self.mgr.unregister_modules(self.owner)

    def test_injected_class_warns_but_accepted(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            accepted = self.mgr.register_module(_InjectedModule, self.owner)
        # 软废弃：仍接受进注册表（零插件破坏）
        self.assertTrue(accepted)
        self.assertIn(_InjectedModule.__name__, self.mgr.get_external_module_ids(self.owner))
        # 但发出废弃提醒
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))

    def test_valid_class_no_deprecation(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            accepted = self.mgr.register_module(_ValidModule, self.owner)
        self.assertTrue(accepted)
        self.assertFalse(any(issubclass(w.category, DeprecationWarning) for w in caught))

    def test_injected_class_accepted_even_when_warnings_are_errors(self):
        """-W error::DeprecationWarning 下告警升格为异常，也不得阻断注册（零破坏铁律）。"""
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            accepted = self.mgr.register_module(_InjectedModule, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_InjectedModule.__name__, self.mgr.get_external_module_ids(self.owner))
