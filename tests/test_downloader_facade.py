# -*- coding: utf-8 -*-
"""
下载器门面 DownloaderManager 回归测试。

核心是 **等价性测试**：证明门面 _dispatch 与 ChainBase.run_module 在各返回形态下结果全等——
门面调用的是与 run_module 同一批后端模块方法，唯一可能分歧的是分发/合并逻辑，本测试以受控
mock 后端覆盖 None / 列表合并 / bool 短路 / tuple 短路 / dict 短路 / 优先级排序 各分支，
锁死"门面 == run_module"。另含：公开方法路由、后端异常逐个续跑、raise_exception 透传、
内建 qb/tr/rtorrent 结构化满足 IDownloader 契约。
"""
from unittest import TestCase

from app.chain import ChainBase
from app.core.module import ModuleManager
from app.managers import DownloaderManager
from app.modules import IDownloader, _ModuleBase
from app.schemas.types import ModuleType


class _TestChain(ChainBase):
    """用于对照 run_module 的可实例化 ChainBase 子类。"""
    pass


class _ProbeBackend(_ModuleBase):
    """
    受控 mock 下载器后端：以自定义 probe 方法承载各返回形态，priority/name 可配置。
    probe 对列表返回值每次返回新副本，避免 run_module 的 result.extend 原地修改污染
    后续（门面）调用的返回值。
    """

    def __init__(self, name="mock", priority=1, probe_return=None, raises=False):
        super().__init__()
        self._name = name
        self._priority = priority
        self._probe_return = probe_return
        self._raises = raises
        self.probe_calls = []

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self):
        pass

    def test(self):
        return True, ""

    def get_name(self):
        return self._name

    def get_priority(self):
        return self._priority

    def get_type(self):
        return ModuleType.Downloader

    def probe(self, *args, **kwargs):
        self.probe_calls.append(kwargs)
        if self._raises:
            raise RuntimeError(f"{self._name} boom")
        ret = self._probe_return
        return list(ret) if isinstance(ret, list) else ret


class _DownloaderBackend(_ModuleBase):
    """实现真实下载器方法名的 mock 后端，用于验证门面公开方法的路由与传参。"""

    def __init__(self, name="dl"):
        super().__init__()
        self._name = name
        self.calls = {}

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self):
        pass

    def test(self):
        return True, ""

    def get_name(self):
        return self._name

    def get_priority(self):
        return 1

    def get_type(self):
        return ModuleType.Downloader

    def download(self, **kwargs):
        self.calls["download"] = kwargs
        return ("dl", "HASH", "layout", "")

    def list_torrents(self, **kwargs):
        self.calls["list_torrents"] = kwargs
        return ["t1"]

    def remove_torrents(self, **kwargs):
        self.calls["remove_torrents"] = kwargs
        return True

    def downloader_info(self, **kwargs):
        self.calls["downloader_info"] = kwargs
        return ["info"]

    def transfer_completed(self, **kwargs):
        self.calls["transfer_completed"] = kwargs
        return None


def _patch_running(backends):
    """把给定后端注入 ModuleManager 单例的 _running_modules，返回 (mgr, 原字典) 以便还原。"""
    mgr = ModuleManager()
    orig = mgr._running_modules
    mgr._running_modules = {b._name: b for b in backends}
    return mgr, orig


class TestDispatchEquivalence(TestCase):
    """门面 _dispatch 与 ChainBase.run_module 行为等价。"""

    def _both(self, backends, **kwargs):
        mgr, orig = _patch_running(backends)
        try:
            chain = _TestChain()
            via_run_module = chain.run_module("probe", **kwargs)
            via_facade = DownloaderManager()._dispatch("probe", **kwargs)
            return via_run_module, via_facade
        finally:
            mgr._running_modules = orig

    def test_all_none(self):
        rm, fc = self._both([_ProbeBackend("a", 1, None), _ProbeBackend("b", 2, None)])
        self.assertIsNone(rm)
        self.assertEqual(rm, fc)

    def test_list_merge_two_backends(self):
        rm, fc = self._both([_ProbeBackend("a", 1, [1, 2]), _ProbeBackend("b", 2, [3])])
        self.assertEqual(rm, [1, 2, 3])
        self.assertEqual(rm, fc)

    def test_list_merge_with_leading_none(self):
        rm, fc = self._both([
            _ProbeBackend("a", 1, None),
            _ProbeBackend("b", 2, [3, 4]),
            _ProbeBackend("c", 3, [5]),
        ])
        self.assertEqual(rm, [3, 4, 5])
        self.assertEqual(rm, fc)

    def test_bool_short_circuit(self):
        # 首个非空非列表（bool）短路，后续列表不应被合并
        rm, fc = self._both([_ProbeBackend("a", 1, True), _ProbeBackend("b", 2, [9])])
        self.assertEqual(rm, True)
        self.assertEqual(rm, fc)

    def test_tuple_short_circuit(self):
        rm, fc = self._both([_ProbeBackend("a", 1, ("x", "y")), _ProbeBackend("b", 2, ("z", "w"))])
        self.assertEqual(rm, ("x", "y"))
        self.assertEqual(rm, fc)

    def test_all_none_tuple_treated_empty(self):
        # 全 None 元组视为空 → 继续下一后端（与 __is_valid_empty 一致）
        rm, fc = self._both([
            _ProbeBackend("a", 1, (None, None)),
            _ProbeBackend("b", 2, ("got", None)),
        ])
        self.assertEqual(rm, ("got", None))
        self.assertEqual(rm, fc)

    def test_dict_result(self):
        rm, fc = self._both([_ProbeBackend("a", 1, None), _ProbeBackend("b", 2, {"x": True})])
        self.assertEqual(rm, {"x": True})
        self.assertEqual(rm, fc)

    def test_priority_ordering(self):
        # 以插入逆序提供，应按 priority 升序遍历得到 [low_priority_first]
        rm, fc = self._both([
            _ProbeBackend("late", 9, [99]),
            _ProbeBackend("early", 1, [1]),
        ])
        self.assertEqual(rm, [1, 99])
        self.assertEqual(rm, fc)


class TestPublicMethodRouting(TestCase):
    """门面公开方法路由到正确后端方法并透传参数。"""

    def setUp(self):
        self.backend = _DownloaderBackend("dl")
        self.mgr, self.orig = _patch_running([self.backend])
        self.dm = DownloaderManager()

    def tearDown(self):
        self.mgr._running_modules = self.orig

    def test_download_routes(self):
        from pathlib import Path
        ret = self.dm.download(content="magnet:x", download_dir=Path("/d"), cookie="c", downloader="dl")
        self.assertEqual(ret, ("dl", "HASH", "layout", ""))
        self.assertEqual(self.backend.calls["download"]["content"], "magnet:x")
        self.assertEqual(self.backend.calls["download"]["downloader"], "dl")

    def test_list_torrents_routes(self):
        ret = self.dm.list_torrents(downloader="dl")
        self.assertEqual(ret, ["t1"])
        self.assertIn("list_torrents", self.backend.calls)

    def test_remove_torrents_routes(self):
        ret = self.dm.remove_torrents(hashs="H", downloader="dl")
        self.assertTrue(ret)
        self.assertEqual(self.backend.calls["remove_torrents"]["hashs"], "H")

    def test_downloader_info_routes(self):
        ret = self.dm.downloader_info(downloader="dl")
        self.assertEqual(ret, ["info"])

    def test_transfer_completed_routes(self):
        ret = self.dm.transfer_completed(hashs="H", downloader="dl")
        self.assertIsNone(ret)
        self.assertEqual(self.backend.calls["transfer_completed"]["hashs"], "H")


class TestErrorHandling(TestCase):
    """后端异常逐个续跑；raise_exception 透传。"""

    def test_error_continues_to_next_backend(self):
        backends = [_ProbeBackend("boom", 1, raises=True), _ProbeBackend("ok", 2, "value")]
        mgr, orig = _patch_running(backends)
        try:
            ret = DownloaderManager()._dispatch("probe")
            self.assertEqual(ret, "value")
            # 同样地 run_module 也续跑到下一个后端
            self.assertEqual(_TestChain().run_module("probe"), "value")
        finally:
            mgr._running_modules = orig

    def test_raise_exception_propagates(self):
        backends = [_ProbeBackend("boom", 1, raises=True)]
        mgr, orig = _patch_running(backends)
        try:
            with self.assertRaises(RuntimeError):
                DownloaderManager()._dispatch("probe", raise_exception=True)
        finally:
            mgr._running_modules = orig


class TestIDownloaderContract(TestCase):
    """
    内建下载器模块对 IDownloader 契约的符合度。

    IDownloader 是下载器域的 **最大化** 行为面（11 方法）：门面对外暴露全部，后端按方法名分发、
    可只实现子集（run_module/门面经 get_running_modules(method) 仅纳入实现了该方法的后端）。
    因此强制核心仅 download/list_torrents/remove_torrents（与 verify_downloader_contract 一致），
    其余方法可选。本测试固定该事实：核心方法所有内建下载器必有；完整面仅 qb/tr 满足；
    rtorrent 为部分后端（已知缺 get_torrent_trackers，见其模块 docstring 的 TODO）。
    """

    _CORE = ("download", "list_torrents", "remove_torrents")
    _FULL = (
        "download", "list_torrents", "remove_torrents", "start_torrents", "stop_torrents",
        "set_torrents_tag", "update_torrent", "get_torrent_trackers", "torrent_files",
        "downloader_info", "transfer_completed",
    )

    def test_all_builtins_implement_core(self):
        from app.modules.qbittorrent import QbittorrentModule
        from app.modules.transmission import TransmissionModule
        from app.modules.rtorrent import RtorrentModule
        for cls in (QbittorrentModule, TransmissionModule, RtorrentModule):
            for name in self._CORE:
                self.assertTrue(callable(getattr(cls, name, None)),
                                f"{cls.__name__} 缺少下载器核心方法 {name}")

    def test_all_builtins_satisfy_full_contract(self):
        # rtorrent 的 get_torrent_trackers + torrent_files 归一化已补齐，三后端均完整满足 IDownloader。
        from app.modules.qbittorrent import QbittorrentModule
        from app.modules.transmission import TransmissionModule
        from app.modules.rtorrent import RtorrentModule
        for cls in (QbittorrentModule, TransmissionModule, RtorrentModule):
            missing = [name for name in self._FULL if not callable(getattr(cls, name, None))]
            self.assertEqual(missing, [], f"{cls.__name__} 缺少 IDownloader 方法 {missing}")
            # runtime_checkable Protocol：方法齐全的类应被识别为 IDownloader 子类
            self.assertTrue(issubclass(cls, IDownloader), f"{cls.__name__} 未结构化满足 IDownloader")

    def test_facade_exposes_full_contract(self):
        for name in self._FULL:
            self.assertTrue(callable(getattr(DownloaderManager, name, None)),
                            f"DownloaderManager 缺少 IDownloader 方法 {name}")
