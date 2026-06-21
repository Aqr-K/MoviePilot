# -*- coding: utf-8 -*-
"""
识别/数据源域门面（MediaRecognizeManager）回归：证明 dispatch/async_dispatch 与 ChainBase.run_module/
async_run_module 语义等价。识别是**管道域**：search_* 列表跨源 extend；非列表非空结果短路（首源识别成功
即止）；插件劫持面优先。门面完整复刻 run_module（插件+系统面）以兼容 v2 经 get_module 劫持的识别插件。
"""
import asyncio
from unittest import TestCase
from unittest.mock import MagicMock, patch

from app.managers.mediarecognize_manager import MediaRecognizeManager
from app.schemas.exception import RateLimitExceededException


class _FakeModule:
    """伪数据源后端：任意方法名合成为记录调用的可调用对象。"""

    def __init__(self, name, priority=0, results=None, raises=None):
        self._name = name
        self._priority = priority
        self._results = results or {}
        self._raises = raises or {}
        self.calls = []

    def get_priority(self):
        return self._priority

    def get_name(self):
        return self._name

    def __getattr__(self, method):
        if method.startswith("_") or method in ("get_priority", "get_name"):
            raise AttributeError(method)

        def _call(*args, **kwargs):
            self.calls.append(method)
            if method in self._raises:
                raise self._raises[method]
            return self._results.get(method)

        return _call


def _mgr(system_modules, plugin_modules=None):
    mgr = MediaRecognizeManager()
    fake_mm = MagicMock()
    fake_mm.get_running_modules.return_value = list(system_modules)
    mgr._modulemanager = fake_mm
    pm = MagicMock()
    pm.return_value.get_plugin_modules.return_value = plugin_modules or {}
    return mgr, pm


class MediaRecognizeFacadeTest(TestCase):

    def test_search_medias_extends_across_sources(self):
        a = _FakeModule("A", priority=0, results={"search_medias": [1, 2]})
        b = _FakeModule("B", priority=1, results={"search_medias": [3]})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.search_medias(meta="m")
        self.assertEqual(ret, [1, 2, 3])  # 跨源 extend 合并

    def test_recognize_first_nonempty_scalar_short_circuits(self):
        # 非列表非空结果 → 短路（首源识别成功即止，后续源不再执行）
        a = _FakeModule("A", priority=0, results={"recognize_media": "movie"})
        b = _FakeModule("B", priority=1, results={"recognize_media": "should-not-run"})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.recognize_media(meta="m")
        self.assertEqual(ret, "movie")
        self.assertEqual(b.calls, [])

    def test_plugin_hijack_runs_first_and_short_circuits(self):
        sysmod = _FakeModule("Sys", results={"recognize_media": "sys"})
        hijack = MagicMock(return_value="plugin")
        plugins = {("pid", "P"): {"recognize_media": hijack}}
        mgr, pm = _mgr([sysmod], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.recognize_media(meta="m")
        self.assertEqual(ret, "plugin")            # 插件劫持优先且短路
        self.assertEqual(sysmod.calls, [])

    def test_async_search_medias_extends_across_sources(self):
        a = _FakeModule("A", priority=0, results={"async_search_medias": [1]})
        b = _FakeModule("B", priority=1, results={"async_search_medias": [2]})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = asyncio.run(mgr.async_search_medias(meta="m"))
        self.assertEqual(ret, [1, 2])              # 异步跨源 extend（同步源经线程池）

    def test_async_obtain_images_first_nonempty_short_circuits(self):
        a = _FakeModule("A", priority=0, results={"async_obtain_images": "img"})
        b = _FakeModule("B", priority=1, results={"async_obtain_images": "nope"})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = asyncio.run(mgr.async_obtain_images(mediainfo="x"))
        self.assertEqual(ret, "img")
        self.assertEqual(b.calls, [])

    def test_rate_limit_skipped_quietly(self):
        a = _FakeModule("A", raises={"search_medias": RateLimitExceededException("limited")})
        b = _FakeModule("B", results={"search_medias": [9]})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.search_medias(meta="m")        # 不抛出，限流源跳过
        self.assertEqual(ret, [9])

    def test_exception_isolated_and_continues(self):
        a = _FakeModule("A", raises={"search_medias": RuntimeError("boom")})
        b = _FakeModule("B", results={"search_medias": [7]})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm), \
                patch.object(MediaRecognizeManager, "_handle_system_error") as he:
            ret = mgr.search_medias(meta="m")
        he.assert_called_once()
        self.assertEqual(ret, [7])                   # 异常源被隔离，其它源续跑

    def test_raise_exception_propagates(self):
        a = _FakeModule("A", raises={"recognize_media": RuntimeError("boom")})
        mgr, pm = _mgr([a])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            with self.assertRaises(RuntimeError):
                mgr.recognize_media(meta="m", raise_exception=True)

    def test_plugin_func_receives_raise_exception(self):
        hijack = MagicMock(return_value=None)
        plugins = {("pid", "P"): {"recognize_media": hijack}}
        mgr, pm = _mgr([_FakeModule("Sys")], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            mgr.recognize_media(meta="m", raise_exception=True)
        self.assertTrue(hijack.call_args.kwargs.get("raise_exception"))
