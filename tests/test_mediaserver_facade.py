# -*- coding: utf-8 -*-
"""
媒体服务器门面 MediaServerManager 回归测试。

核心是 **等价性测试**：证明门面 _dispatch 与 ChainBase.run_module 在各返回形态下结果全等——
门面调用的是与 run_module 同一批后端模块方法，唯一可能分歧的是分发/合并逻辑，本测试以受控
mock 后端覆盖 None / 列表合并 / 短路 / tuple / dict / 优先级 / 生成器 各分支，锁死"门面 == run_module"。
另含：公开方法路由、后端异常逐个续跑、raise_exception 透传、内建媒服结构化满足 IMediaServer 契约。
"""
from unittest import TestCase

from app.chain import ChainBase
from app.core.module import ModuleManager
from app.managers.mediaserver_manager import MediaServerManager
from app.modules import IMediaServer, _ModuleBase
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import ModuleType


class _TestChain(ChainBase):
    """用于对照 run_module 的可实例化 ChainBase 子类。"""
    pass


class _ProbeBackend(_ModuleBase):
    """
    受控 mock 媒服后端：以自定义 probe 方法承载各返回形态，priority/name 可配置。
    probe 对列表返回值每次返回新副本、对生成器每次返回新迭代器，避免 run_module 与门面两次
    调用相互污染。
    """

    def __init__(self, name="mock", priority=1, probe_return=None, raises=False,
                 gen_values=None, rate_limit=False):
        super().__init__()
        self._name = name
        self._priority = priority
        self._probe_return = probe_return
        self._raises = raises
        self._gen_values = gen_values
        self._rate_limit = rate_limit
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
        return ModuleType.MediaServer

    def probe(self, *args, **kwargs):
        self.probe_calls.append(kwargs)
        if self._rate_limit:
            raise RateLimitExceededException(f"{self._name} rate limited")
        if self._raises:
            raise RuntimeError(f"{self._name} boom")
        if self._gen_values is not None:
            return (v for v in self._gen_values)
        ret = self._probe_return
        return list(ret) if isinstance(ret, list) else ret


class _MediaServerBackend(_ModuleBase):
    """实现真实媒服方法名的 mock 后端，用于验证门面公开方法的路由与传参。"""

    def __init__(self, name="ms"):
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
        return ModuleType.MediaServer

    def mediaserver_librarys(self, **kwargs):
        self.calls["mediaserver_librarys"] = kwargs
        return ["lib"]

    def media_statistic(self, **kwargs):
        self.calls["media_statistic"] = kwargs
        return ["stat"]

    def mediaserver_play_url(self, **kwargs):
        self.calls["mediaserver_play_url"] = kwargs
        return "http://play"

    def mediaserver_items(self, **kwargs):
        self.calls["mediaserver_items"] = kwargs
        return (i for i in ["it1", "it2"])


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
            via_facade = MediaServerManager()._dispatch("probe", **kwargs)
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

    def test_str_short_circuit(self):
        # 首个非空非列表（str，如 play_url）短路，后续不应合并
        rm, fc = self._both([_ProbeBackend("a", 1, "http://x"), _ProbeBackend("b", 2, [9])])
        self.assertEqual(rm, "http://x")
        self.assertEqual(rm, fc)

    def test_tuple_short_circuit(self):
        rm, fc = self._both([_ProbeBackend("a", 1, ("x", "y")), _ProbeBackend("b", 2, ("z", "w"))])
        self.assertEqual(rm, ("x", "y"))
        self.assertEqual(rm, fc)

    def test_all_none_tuple_treated_empty(self):
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
        rm, fc = self._both([
            _ProbeBackend("late", 9, [99]),
            _ProbeBackend("early", 1, [1]),
        ])
        self.assertEqual(rm, [1, 99])
        self.assertEqual(rm, fc)

    def test_generator_leading_none(self):
        # mediaserver_items 形态：前置 None 后端 + 返回生成器的后端 → 取该生成器（非列表短路）
        rm, fc = self._both([
            _ProbeBackend("a", 1, None),
            _ProbeBackend("b", 2, gen_values=["it1", "it2"]),
        ])
        self.assertEqual(list(rm), ["it1", "it2"])
        self.assertEqual(list(fc), ["it1", "it2"])


class TestPublicMethodRouting(TestCase):
    """门面公开方法路由到正确后端方法并透传参数。"""

    def setUp(self):
        self.backend = _MediaServerBackend("ms")
        self.mgr, self.orig = _patch_running([self.backend])
        self.msm = MediaServerManager()

    def tearDown(self):
        self.mgr._running_modules = self.orig

    def test_librarys_routes(self):
        ret = self.msm.mediaserver_librarys(server="emby1", username="u", hidden=True)
        self.assertEqual(ret, ["lib"])
        self.assertEqual(self.backend.calls["mediaserver_librarys"]["server"], "emby1")
        self.assertEqual(self.backend.calls["mediaserver_librarys"]["username"], "u")

    def test_media_statistic_routes(self):
        ret = self.msm.media_statistic(server="emby1")
        self.assertEqual(ret, ["stat"])
        self.assertEqual(self.backend.calls["media_statistic"]["server"], "emby1")

    def test_play_url_routes(self):
        ret = self.msm.mediaserver_play_url(server="emby1", item_id="123")
        self.assertEqual(ret, "http://play")
        self.assertEqual(self.backend.calls["mediaserver_play_url"]["item_id"], "123")

    def test_items_routes_generator(self):
        ret = self.msm.mediaserver_items(server="emby1", library_id="1")
        self.assertEqual(list(ret), ["it1", "it2"])


class TestErrorHandling(TestCase):
    """后端异常逐个续跑；raise_exception 透传。"""

    def test_error_continues_to_next_backend(self):
        backends = [_ProbeBackend("boom", 1, raises=True), _ProbeBackend("ok", 2, "value")]
        mgr, orig = _patch_running(backends)
        try:
            self.assertEqual(MediaServerManager()._dispatch("probe"), "value")
            self.assertEqual(_TestChain().run_module("probe"), "value")
        finally:
            mgr._running_modules = orig

    def test_raise_exception_propagates(self):
        backends = [_ProbeBackend("boom", 1, raises=True)]
        mgr, orig = _patch_running(backends)
        try:
            with self.assertRaises(RuntimeError):
                MediaServerManager()._dispatch("probe", raise_exception=True)
        finally:
            mgr._running_modules = orig

    def test_rate_limit_skipped_quietly_equivalence(self):
        # 限流异常应安静跳过（不当系统错误、不中止），续跑到下一后端——与 run_module 完全一致
        backends = [_ProbeBackend("limited", 1, rate_limit=True), _ProbeBackend("ok", 2, "value")]
        mgr, orig = _patch_running(backends)
        try:
            self.assertEqual(MediaServerManager()._dispatch("probe"), "value")
            self.assertEqual(_TestChain().run_module("probe"), "value")
        finally:
            mgr._running_modules = orig

    def test_rate_limit_raise_exception_propagates(self):
        backends = [_ProbeBackend("limited", 1, rate_limit=True)]
        mgr, orig = _patch_running(backends)
        try:
            with self.assertRaises(RateLimitExceededException):
                MediaServerManager()._dispatch("probe", raise_exception=True)
        finally:
            mgr._running_modules = orig


class TestIMediaServerContract(TestCase):
    """
    内建媒服模块对 IMediaServer 契约的符合度。

    IMediaServer 是媒服域的 **最大化** 行为面（11 方法）：门面对外暴露全部，后端按方法名分发、
    可只实现子集。10 个通用方法所有内建后端必有；mediaserver_image_cookies 仅 TrimeMedia/Ugreen 实现
    （部分后端，类比下载器域 rtorrent 早期缺方法）。
    """

    _UNIVERSAL = (
        "media_exists", "media_statistic", "mediaserver_librarys", "mediaserver_items",
        "mediaserver_iteminfo", "mediaserver_tv_episodes", "mediaserver_playing",
        "mediaserver_play_url", "mediaserver_latest", "mediaserver_latest_images",
    )
    _FULL = _UNIVERSAL + ("mediaserver_image_cookies",)

    def _builtins(self):
        from app.modules.emby import EmbyModule
        from app.modules.jellyfin import JellyfinModule
        from app.modules.plex import PlexModule
        from app.modules.trimemedia import TrimeMediaModule
        from app.modules.ugreen import UgreenModule
        from app.modules.zspace import ZSpaceModule
        return [EmbyModule, JellyfinModule, PlexModule, TrimeMediaModule, UgreenModule, ZSpaceModule]

    def test_all_builtins_implement_universal(self):
        for cls in self._builtins():
            for name in self._UNIVERSAL:
                self.assertTrue(callable(getattr(cls, name, None)),
                                f"{cls.__name__} 缺少媒服通用方法 {name}")

    def test_image_cookies_partial(self):
        from app.modules.trimemedia import TrimeMediaModule
        from app.modules.ugreen import UgreenModule
        from app.modules.emby import EmbyModule
        self.assertTrue(callable(getattr(TrimeMediaModule, "mediaserver_image_cookies", None)))
        self.assertTrue(callable(getattr(UgreenModule, "mediaserver_image_cookies", None)))
        # Emby 不实现该可选方法
        self.assertFalse(callable(getattr(EmbyModule, "mediaserver_image_cookies", None)))

    def test_facade_exposes_full_face(self):
        for name in self._FULL:
            self.assertTrue(callable(getattr(MediaServerManager, name, None)),
                            f"MediaServerManager 缺少 IMediaServer 方法 {name}")

    def test_full_face_backends_satisfy_protocol(self):
        # 实现全部 11 方法的后端应结构化满足 IMediaServer（runtime_checkable）
        from app.modules.trimemedia import TrimeMediaModule
        from app.modules.ugreen import UgreenModule
        for cls in (TrimeMediaModule, UgreenModule):
            self.assertTrue(issubclass(cls, IMediaServer), f"{cls.__name__} 未结构化满足 IMediaServer")
