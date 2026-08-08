# -*- coding: utf-8 -*-
"""
储存域门面（StorageManager）回归：证明 dispatch 与 ChainBase.run_module 语义等价。储存域只有一个系统
模块 FileManagerModule（schema 路由在其内部），但门面仍**完整复刻 run_module（插件劫持面 + 系统面）**——
储存/整理域是 v2 插件经 get_module 劫持方法槽的重灾区（如 p115 接入 115），改接后须零破坏这些插件。
"""
from unittest import TestCase
from unittest.mock import MagicMock, patch

from app.managers import StorageManager
from app.schemas.exception import RateLimitExceededException


class _FakeModule:
    """伪储存后端：任意方法名合成为记录调用的可调用对象。"""

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
    mgr = StorageManager()
    fake_mm = MagicMock()
    fake_mm.get_running_modules.return_value = list(system_modules)
    mgr._modulemanager = fake_mm
    pm = MagicMock()
    pm.return_value.get_plugin_modules.return_value = plugin_modules or {}
    return mgr, pm


class StorageFacadeTest(TestCase):

    def test_list_files_dispatches_to_storage_module(self):
        fm = _FakeModule("FileManager", results={"list_files": ["a", "b"]})
        mgr, pm = _mgr([fm])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.list_files(fileitem="x", recursion=False)
        self.assertEqual(ret, ["a", "b"])
        self.assertEqual(fm.calls, ["list_files"])

    def test_delete_file_first_nonempty_short_circuits(self):
        fm = _FakeModule("FileManager", results={"delete_file": True})
        mgr, pm = _mgr([fm])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.delete_file(fileitem="x")
        self.assertIs(ret, True)

    def test_plugin_hijack_list_extends_system(self):
        # 储存域 get_module 劫持重灾区：插件劫持 list_files 返回 list → 与系统结果 extend 合并
        fm = _FakeModule("FileManager", results={"list_files": ["sys"]})
        hijack = MagicMock(return_value=["plugin"])
        plugins = {("p115", "P115StrmHelper"): {"list_files": hijack}}
        mgr, pm = _mgr([fm], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.list_files(fileitem="x")
        self.assertEqual(ret, ["plugin", "sys"])   # 与 run_module 一致：list 不短路、跨面合并
        self.assertEqual(fm.calls, ["list_files"])

    def test_plugin_hijack_scalar_short_circuits_system(self):
        fm = _FakeModule("FileManager", results={"delete_file": True})
        hijack = MagicMock(return_value=False)
        plugins = {("p115", "P"): {"delete_file": hijack}}
        mgr, pm = _mgr([fm], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.delete_file(fileitem="x")
        self.assertIs(ret, False)                  # 插件非空非列表 → 短路
        self.assertEqual(fm.calls, [])

    def test_rate_limit_skipped_quietly(self):
        fm = _FakeModule("FileManager", raises={"storage_usage": RateLimitExceededException("limited")})
        mgr, pm = _mgr([fm])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.storage_usage(storage="u115")   # 不抛出
        self.assertIsNone(ret)

    def test_exception_isolated(self):
        fm = _FakeModule("FileManager", raises={"list_files": RuntimeError("boom")})
        mgr, pm = _mgr([fm])
        with patch("app.helper.plugin_manager.PluginManager", pm), \
                patch.object(StorageManager, "_handle_system_error") as he:
            mgr.list_files(fileitem="x")
        he.assert_called_once()

    def test_raise_exception_propagates(self):
        fm = _FakeModule("FileManager", raises={"list_files": RuntimeError("boom")})
        mgr, pm = _mgr([fm])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            with self.assertRaises(RuntimeError):
                mgr.list_files(fileitem="x", raise_exception=True)

    def test_plugin_func_receives_raise_exception(self):
        hijack = MagicMock(return_value=None)
        plugins = {("p115", "P"): {"list_files": hijack}}
        mgr, pm = _mgr([_FakeModule("FileManager")], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            mgr.list_files(fileitem="x", raise_exception=True)
        self.assertTrue(hijack.call_args.kwargs.get("raise_exception"))
