# -*- coding: utf-8 -*-
"""
Q1-S5 回归测试：FileManager 存储器二级源（外部/插件存储器开放注册）。

验证：
  1. FileManagerModule.register_storage(cls, owner) 后，外部存储 schema 进入运行实例的
     _storage_schemas/_support_storages，__get_storage_oper 可命中（merge 非 replace）；
  2. unregister_storages(owner) 后外部存储下线；
  3. 6 个内建存储器（local/alipan/u115/rclone/alist/smb）不受影响；
  4. PluginManager._register_plugin_modules 接通 provides_storages → FileManager 注册，
     _unregister_plugin_modules 卸载。
  存储器开放无需扩展 StorageSchema 封闭枚举：__get_storage_oper 按 schema.value 字符串匹配，
  插件存储类只要 .schema.value 为其字符串 id 即可。
"""
from types import SimpleNamespace
from unittest import TestCase

from app.core.module import ModuleManager
from app.helper.plugin_manager import PluginManager
from app.modules.filemanager import FileManagerModule
from app.modules.filemanager.storages import StorageBase


class _FakeWebdavStorage(StorageBase):
    """插件式外部存储：schema.value='webdav'（枚举外），跳过 StorageHelper 初始化"""

    schema = SimpleNamespace(value="webdav")
    transtype = {"copy": "复制"}

    def __init__(self):
        # 跳过 StorageBase.__init__ 的 StorageHelper，保持测试轻量
        pass

    def init_storage(self):
        pass

    def support_transtype(self):
        return self.transtype


# StorageBase(ABCMeta) 有大量抽象方法（check/copy/list/...）；真插件存储类会全部实现，
# 此处测试假类清空抽象集合以便实例化（继承的方法均为 no-op 返回 None）。
_FakeWebdavStorage.__abstractmethods__ = frozenset()


class _FakeStoragePlugin:
    def get_state(self) -> bool:
        return True

    def get_name(self) -> str:
        return "FakeStoragePlugin"

    def provides_modules(self):
        return []

    def provides_storages(self):
        return [_FakeWebdavStorage]


_OWNER = "test.plugin.q1s5"
_BUILTIN = {"local", "alipan", "u115", "rclone", "alist", "smb"}


class FileManagerExternalStorageTest(TestCase):

    def setUp(self):
        self.mm = ModuleManager()
        self.fm = self.mm.get_running_module("FileManagerModule")
        self.assertIsNotNone(self.fm, "FileManagerModule 应处于运行态（init_setting 无开关，始终加载）")

    def tearDown(self):
        FileManagerModule.unregister_storages(_OWNER)

    def test_register_storage_merges(self):
        FileManagerModule.register_storage(_FakeWebdavStorage, owner=_OWNER)
        self.assertIn("webdav", self.fm._support_storages)
        self.assertIn(_FakeWebdavStorage, self.fm._storage_schemas)
        # __get_storage_oper（name-mangled 私有）能命中外部存储
        oper = self.fm._FileManagerModule__get_storage_oper("webdav")
        self.assertIsInstance(oper, _FakeWebdavStorage)

    def test_unregister_storage(self):
        FileManagerModule.register_storage(_FakeWebdavStorage, owner=_OWNER)
        FileManagerModule.unregister_storages(_OWNER)
        self.assertNotIn("webdav", self.fm._support_storages)
        self.assertNotIn(_FakeWebdavStorage, self.fm._storage_schemas)

    def test_builtin_storages_unaffected(self):
        before = set(self.fm._support_storages)
        self.assertTrue(_BUILTIN.issubset(before), f"内建存储缺失：{_BUILTIN - before}")
        FileManagerModule.register_storage(_FakeWebdavStorage, owner=_OWNER)
        self.assertTrue(_BUILTIN.issubset(set(self.fm._support_storages)))
        FileManagerModule.unregister_storages(_OWNER)
        self.assertTrue(_BUILTIN.issubset(set(self.fm._support_storages)))

    def test_plugin_manager_wires_storages(self):
        pm = PluginManager()
        saved = dict(pm._running_plugins)
        try:
            pm._running_plugins = {_OWNER: _FakeStoragePlugin()}
            pm._register_plugin_modules()
            self.assertIn("webdav", self.fm._support_storages)
            pm._unregister_plugin_modules([_OWNER])
            self.assertNotIn("webdav", self.fm._support_storages)
        finally:
            pm._running_plugins = saved
            FileManagerModule.unregister_storages(_OWNER)
