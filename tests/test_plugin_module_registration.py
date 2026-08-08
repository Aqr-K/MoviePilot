# -*- coding: utf-8 -*-
"""
Q1-S4 回归测试：PluginManager 生命周期 ↔ ModuleManager 注册接线（运行期动态上下线）。

验证：
  1. _register_plugin_modules() 把运行态插件经 provides_modules 声明的模块注册进 ModuleManager
     （owner=plugin_id），随即进入 chain 分发；
  2. 未启用插件(get_state=False)的模块不被注册；
  3. _unregister_plugin_modules([pid]) 卸载该插件的模块；
  4. stop(pid) 卸载该插件注册的模块（无僵尸）；
  5. 运行期 init_plugin(pid) 重同步：插件由启用转禁用后，其模块被下线。
"""
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_manager import PluginManager
from app.modules import _ModuleBase
from app.schemas.types import ModuleType, DownloaderType


class _PluginDownloaderModule(_ModuleBase):
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
        return DownloaderType.Qbittorrent

    @staticmethod
    def get_priority() -> int:
        return 99

    def download(self, *args, **kwargs):
        return "plugin-download"


class _FakePlugin:
    plugin_version = "1.0"

    def __init__(self, state=True):
        self._state = state

    def get_state(self) -> bool:
        return self._state

    def get_name(self) -> str:
        return "FakePlugin"

    def init_plugin(self, conf=None):
        pass

    def provides_modules(self):
        return [_PluginDownloaderModule]

    def provides_storages(self):
        return []


_PID = "test.plugin.q1s4"


class PluginModuleRegistrationTest(TestCase):

    def setUp(self):
        self.pm = PluginManager()
        self.mm = ModuleManager()
        # 保存并隔离运行态插件字典，避免污染真实单例
        self._saved_running = dict(self.pm._running_plugins)

    def tearDown(self):
        self.mm.unregister_modules(_PID)
        self.pm._running_plugins = self._saved_running

    def _running_module_types(self):
        return [type(m) for m in self.mm.get_running_modules("download")]

    def test_register_via_helper(self):
        self.pm._running_plugins = {_PID: _FakePlugin(state=True)}
        self.pm._register_plugin_modules()
        self.assertIn("_PluginDownloaderModule", self.mm.get_external_module_ids(_PID))
        self.assertIn(_PluginDownloaderModule, self._running_module_types())

    def test_disabled_not_registered(self):
        self.pm._running_plugins = {_PID: _FakePlugin(state=False)}
        self.pm._register_plugin_modules()
        self.assertEqual(self.mm.get_external_module_ids(_PID), [])
        self.assertNotIn(_PluginDownloaderModule, self._running_module_types())

    def test_unregister_via_helper(self):
        self.pm._running_plugins = {_PID: _FakePlugin(state=True)}
        self.pm._register_plugin_modules()
        self.pm._unregister_plugin_modules([_PID])
        self.assertEqual(self.mm.get_external_module_ids(_PID), [])
        self.assertNotIn(_PluginDownloaderModule, self._running_module_types())

    def test_stop_unregisters(self):
        self.pm._running_plugins = {_PID: _FakePlugin(state=True)}
        self.pm._register_plugin_modules()
        self.assertIn(_PluginDownloaderModule, self._running_module_types())
        # 停止该插件应一并卸载其模块
        self.pm.stop(_PID)
        self.assertEqual(self.mm.get_external_module_ids(_PID), [])
        self.assertNotIn(_PluginDownloaderModule, self._running_module_types())

    def test_runtime_disable_resync(self):
        fake = _FakePlugin(state=True)
        self.pm._running_plugins = {_PID: fake}
        self.pm._register_plugin_modules()
        self.assertIn(_PluginDownloaderModule, self._running_module_types())
        # 运行期把插件切到禁用，再触发 init_plugin 重同步 → 模块下线
        fake._state = False
        self.pm.init_plugin(_PID, {})
        self.assertNotIn(_PluginDownloaderModule, self._running_module_types())
        self.assertEqual(self.mm.get_external_module_ids(_PID), [])
