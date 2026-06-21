# -*- coding: utf-8 -*-
"""
通知域门面（NotificationManager）回归：证明 dispatch 与 ChainBase.run_module 语义等价。

与下载器/媒服门面不同，通知门面**完整复刻 run_module（插件劫持面 + 系统面）**以兼容 v2 经
get_module 劫持 post_message 的现存插件。本测试覆盖：广播（post_*）、插件劫持优先且短路、
插件返回 None 落到系统面、delete_message 取首个非空短路、限流安静跳过、异常隔离续跑、raise 透传。
"""
from unittest import TestCase
from unittest.mock import MagicMock, patch

from app.helper.notification_manager import NotificationManager
from app.schemas.exception import RateLimitExceededException


class _FakeModule:
    """伪通知后端：任意方法名合成为记录调用的可调用对象。"""

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
    """构造一个 NotificationManager，注入伪系统模块 + 伪插件劫持表。"""
    mgr = NotificationManager()
    fake_mm = MagicMock()
    fake_mm.get_running_modules.return_value = list(system_modules)
    mgr._modulemanager = fake_mm
    pm = MagicMock()
    pm.return_value.get_plugin_modules.return_value = plugin_modules or {}
    return mgr, pm


class NotificationFacadeTest(TestCase):

    def test_post_message_broadcasts_all_system_modules(self):
        a = _FakeModule("A")
        b = _FakeModule("B")
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.post_message(message="m")
        self.assertIsNone(ret)
        self.assertEqual(a.calls, ["post_message"])  # 广播：两个渠道都被调用
        self.assertEqual(b.calls, ["post_message"])

    def test_plugin_hijack_runs_first_and_short_circuits(self):
        # 插件劫持返回非空非列表 → 短路，系统模块不再执行（复刻 run_module 行为）
        sysmod = _FakeModule("Sys", results={"delete_message": True})
        hijack = MagicMock(return_value=True)
        plugins = {("pid", "PluginName"): {"delete_message": hijack}}
        mgr, pm = _mgr([sysmod], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.delete_message(channel="c", message_id=1)
        self.assertIs(ret, True)
        hijack.assert_called_once()
        self.assertEqual(sysmod.calls, [])  # 系统面被短路

    def test_plugin_returns_none_falls_through_to_system(self):
        sysmod = _FakeModule("Sys", results={"post_message": None})
        hijack = MagicMock(return_value=None)
        plugins = {("pid", "PluginName"): {"post_message": hijack}}
        mgr, pm = _mgr([sysmod], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            mgr.post_message(message="m")
        hijack.assert_called_once()
        self.assertEqual(sysmod.calls, ["post_message"])  # 插件返回 None → 系统面继续

    def test_delete_message_first_non_empty_short_circuits(self):
        a = _FakeModule("A", priority=0, results={"delete_message": True})
        b = _FakeModule("B", priority=1, results={"delete_message": False})
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.delete_message(channel="c", message_id=1)
        self.assertIs(ret, True)
        self.assertEqual(a.calls, ["delete_message"])
        self.assertEqual(b.calls, [])  # 首个非空即短路

    def test_rate_limit_skipped_quietly(self):
        a = _FakeModule("A", raises={"post_message": RateLimitExceededException("limited")})
        b = _FakeModule("B")
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            ret = mgr.post_message(message="m")  # 不抛出
        self.assertIsNone(ret)
        self.assertEqual(b.calls, ["post_message"])  # 限流后续渠道仍执行

    def test_exception_isolated_and_continues(self):
        a = _FakeModule("A", raises={"post_message": RuntimeError("boom")})
        b = _FakeModule("B")
        mgr, pm = _mgr([a, b])
        with patch("app.helper.plugin_manager.PluginManager", pm), \
                patch.object(NotificationManager, "_handle_system_error") as he:
            mgr.post_message(message="m")
        he.assert_called_once()              # 异常被错误处理器吞下
        self.assertEqual(b.calls, ["post_message"])  # 其它渠道续跑

    def test_raise_exception_propagates(self):
        a = _FakeModule("A", raises={"post_message": RuntimeError("boom")})
        mgr, pm = _mgr([a])
        with patch("app.helper.plugin_manager.PluginManager", pm):
            with self.assertRaises(RuntimeError):
                mgr.post_message(message="m", raise_exception=True)

    def test_plugin_func_receives_raise_exception(self):
        # 与 run_module 一致：raise_exception 透传给插件劫持 func（插件可据此决定内部异常是否上抛）。
        hijack = MagicMock(return_value=None)
        plugins = {("pid", "PluginName"): {"post_message": hijack}}
        mgr, pm = _mgr([_FakeModule("Sys")], plugins)
        with patch("app.helper.plugin_manager.PluginManager", pm):
            mgr.post_message(message="m", raise_exception=True)
        self.assertTrue(hijack.call_args.kwargs.get("raise_exception"))
