# -*- coding: utf-8 -*-
"""
Q1-S1 回归测试：ModuleManager 外部(插件)模块二级注册核心。

验证：
  1. register_module 后，外部模块进入 _modules/_running_modules，且能被
     get_running_modules(method)/get_running_type_modules/get_running_subtype_module 分发枚举到；
  2. reload() 后外部模块仍在（类记账 + 重放，挺过全量重扫）；
  3. unregister_modules(owner) 后外部模块下线，无僵尸；
  4. 外部类 init_module 抛异常被隔离，不影响内建模块加载；
  5. 同 owner 重复注册幂等（不产生重复记账）；
  6. 命名冲突（module_id 已存在且非本 owner）被拒绝，原模块完好；
  7. 运行期并发 register/unregister 与分发迭代不抛 "dictionary changed size"。
"""
import threading
from unittest import TestCase

from app.core.module import ModuleManager
from app.modules import _ModuleBase
from app.schemas.types import ModuleType, DownloaderType


class _DummyDownloaderModule(_ModuleBase):
    """最小可分发的外部下载器模块（无开关，始终加载）"""

    inited = False
    stopped = False

    def init_module(self) -> None:
        type(self).inited = True

    def init_setting(self):
        return None  # 无开关 → check_setting 返回 True，始终加载

    def stop(self) -> None:
        type(self).stopped = True

    def test(self):
        return True, ""

    @staticmethod
    def get_name() -> str:
        return "DummyDownloader"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader

    @staticmethod
    def get_subtype() -> DownloaderType:
        return DownloaderType.Qbittorrent

    @staticmethod
    def get_priority() -> int:
        return 99

    def download(self, *args, **kwargs):
        return "dummy-download"


class _BrokenModule(_ModuleBase):
    """init_module 抛异常的外部模块，用于验证隔离性"""

    def init_module(self) -> None:
        raise RuntimeError("boom")

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader


_OWNER = "test.plugin.q1s1"
_OWNER2 = "test.plugin.q1s1.other"


class ModuleExternalRegistrationTest(TestCase):

    def setUp(self):
        self.mm = ModuleManager()
        _DummyDownloaderModule.inited = False
        _DummyDownloaderModule.stopped = False

    def tearDown(self):
        # 清理本测试注册的外部模块，避免污染共享单例
        self.mm.unregister_modules(_OWNER)
        self.mm.unregister_modules(_OWNER2)

    def test_register_enters_modules_and_dispatch(self):
        ok = self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        self.assertTrue(ok)
        # 进入 _modules 与运行态
        self.assertIn("_DummyDownloaderModule", self.mm.get_module_ids())
        self.assertIn("_DummyDownloaderModule", self.mm.get_external_module_ids(_OWNER))
        self.assertTrue(_DummyDownloaderModule.inited)
        # 按方法名分发可枚举到
        method_modules = list(self.mm.get_running_modules("download"))
        self.assertIn(_DummyDownloaderModule, [type(m) for m in method_modules])
        # 按类型分发
        type_modules = list(self.mm.get_running_type_modules(ModuleType.Downloader))
        self.assertIn(_DummyDownloaderModule, [type(m) for m in type_modules])
        # 按子类型分发（与内建 Qbittorrent 共存，断言 dummy 在其中）
        subtype_modules = list(self.mm.get_running_subtype_module(DownloaderType.Qbittorrent))
        self.assertIn(_DummyDownloaderModule, [type(m) for m in subtype_modules])

    def test_reload_replays_external_modules(self):
        self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        self.assertIn("_DummyDownloaderModule", self.mm.get_module_ids())
        # reload 会全量重扫 app.modules 并重置 _modules/_running_modules
        self.mm.reload()
        # 外部模块应被重放回来
        self.assertIn("_DummyDownloaderModule", self.mm.get_module_ids())
        running = [type(m) for m in self.mm.get_running_modules("download")]
        self.assertIn(_DummyDownloaderModule, running)

    def test_unregister_removes_module(self):
        self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        removed = self.mm.unregister_modules(_OWNER)
        self.assertIn("_DummyDownloaderModule", removed)
        self.assertNotIn("_DummyDownloaderModule", self.mm.get_module_ids())
        self.assertEqual(self.mm.get_external_module_ids(_OWNER), [])
        self.assertTrue(_DummyDownloaderModule.stopped)
        running = [type(m) for m in self.mm.get_running_modules("download")]
        self.assertNotIn(_DummyDownloaderModule, running)

    def test_broken_module_isolated(self):
        builtin_before = set(self.mm.get_module_ids())
        ok = self.mm.register_module(_BrokenModule, owner=_OWNER)
        # 接受进注册表（记账成功），但未进入运行态
        self.assertTrue(ok)
        running = [type(m) for m in self.mm.get_running_modules("download")]
        self.assertNotIn(_BrokenModule, running)
        # 内建模块不受影响
        self.assertTrue(builtin_before.issubset(set(self.mm.get_module_ids())))

    def test_idempotent_register(self):
        self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        self.assertEqual(self.mm.get_external_module_ids(_OWNER).count("_DummyDownloaderModule"), 1)

    def test_collision_rejected(self):
        self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
        # 另一 owner 试图注册同名 module_id → 拒绝
        ok = self.mm.register_module(_DummyDownloaderModule, owner=_OWNER2)
        self.assertFalse(ok)
        # 原归属不变
        self.assertIn("_DummyDownloaderModule", self.mm.get_external_module_ids(_OWNER))
        self.assertEqual(self.mm.get_external_module_ids(_OWNER2), [])

    def test_concurrent_register_unregister_no_race(self):
        errors = []

        def churn():
            try:
                for _ in range(100):
                    self.mm.register_module(_DummyDownloaderModule, owner=_OWNER)
                    self.mm.unregister_modules(_OWNER)
            except Exception as err:  # pragma: no cover - 只在出错时记录
                errors.append(err)

        def iterate():
            try:
                for _ in range(100):
                    list(self.mm.get_running_modules("download"))
                    list(self.mm.get_running_type_modules(ModuleType.Downloader))
            except Exception as err:  # pragma: no cover
                errors.append(err)

        threads = [threading.Thread(target=churn), threading.Thread(target=iterate)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"并发读写抛异常：{errors}")
