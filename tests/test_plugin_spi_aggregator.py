# -*- coding: utf-8 -*-
"""
Q1-S3 回归测试：插件 SPI 声明式扩展点（provides_modules/provides_storages）与只读聚合器。

验证：
  1. _PluginBase 提供默认 provides_modules()/provides_storages()，默认返回 []（老插件零改动）；
  2. get_plugin_provided_modules/get_plugin_provided_storages 聚合运行态插件的声明，按
     plugin_id(owner) 归集为 {plugin_id: [module_cls, ...]}；
  3. 未启用插件(get_state=False)被跳过；
  4. 单插件钩子抛异常被隔离，不影响其它插件聚合；
  5. pid 过滤只聚合指定插件。
"""
from unittest import TestCase

from app.helper.plugin_metadata import (
    get_plugin_provided_modules,
    get_plugin_provided_storages,
)
from app.plugins import _PluginBase


class _DummyModuleA:
    pass


class _DummyModuleB:
    pass


class _DummyStorage:
    pass


class _FakePlugin:
    """duck-typed 运行态插件，仿 _PluginBase 暴露 SPI 钩子"""

    def __init__(self, modules=None, storages=None, state=True, raise_modules=False):
        self._modules = modules or []
        self._storages = storages or []
        self._state = state
        self._raise = raise_modules

    def get_state(self) -> bool:
        return self._state

    def get_name(self) -> str:
        return "FakePlugin"

    def provides_modules(self):
        if self._raise:
            raise RuntimeError("boom")
        return self._modules

    def provides_storages(self):
        return self._storages


class PluginSpiAggregatorTest(TestCase):

    def test_base_defaults_empty(self):
        # 默认实现不依赖 self，直接以未绑定方式校验返回空
        self.assertEqual(_PluginBase.provides_modules(object()), [])
        self.assertEqual(_PluginBase.provides_storages(object()), [])

    def test_aggregates_modules_by_owner(self):
        running = {"plugin.a": _FakePlugin(modules=[_DummyModuleA, _DummyModuleB])}
        result = get_plugin_provided_modules(running)
        self.assertIn("plugin.a", result)
        self.assertEqual(result["plugin.a"], [_DummyModuleA, _DummyModuleB])

    def test_disabled_plugin_excluded(self):
        running = {"plugin.a": _FakePlugin(modules=[_DummyModuleA], state=False)}
        result = get_plugin_provided_modules(running)
        self.assertEqual(result, {})

    def test_error_isolated(self):
        running = {
            "plugin.bad": _FakePlugin(raise_modules=True),
            "plugin.good": _FakePlugin(modules=[_DummyModuleA]),
        }
        result = get_plugin_provided_modules(running)
        self.assertNotIn("plugin.bad", result)
        self.assertIn("plugin.good", result)

    def test_pid_filter(self):
        running = {
            "plugin.a": _FakePlugin(modules=[_DummyModuleA]),
            "plugin.b": _FakePlugin(modules=[_DummyModuleB]),
        }
        result = get_plugin_provided_modules(running, pid="plugin.a")
        self.assertEqual(set(result.keys()), {"plugin.a"})

    def test_storages_aggregated(self):
        running = {"plugin.s": _FakePlugin(storages=[_DummyStorage])}
        result = get_plugin_provided_storages(running)
        self.assertEqual(result["plugin.s"], [_DummyStorage])

    def test_empty_declarations_omitted(self):
        # 声明为空的插件不产生空条目
        running = {"plugin.empty": _FakePlugin(modules=[])}
        result = get_plugin_provided_modules(running)
        self.assertEqual(result, {})
