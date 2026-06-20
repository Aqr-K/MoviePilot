# -*- coding: utf-8 -*-
"""
储存层（Storage 域）注册严格契约校验回归。

储存层 S5(#54) 已有开放注册（FileManagerModule.register_storage + storage_registry
reload-stable + provides_storages 钩子），但注册仅 isinstance(type) 校验、无契约验证——
畸形类会静默入表、待 __get_storage_oper 实例化时炸裂。本次补 verify_storage_contract 并在
register_storage 内部 verify-then-reject，对齐其余各域的 verify_*_contract 严格注册。

验证：
  1. 合法存储器（StorageBase 子类 + abstractmethod 全实现 + 非空 schema）通过；
  2. 非 StorageBase / 抽象方法未实现 / schema 缺失 判定失败并给出原因；
  3. register_storage 对不合格存储器拒绝（返回 False、不入 storage_registry）；
  4. 合法存储器经 register_storage 正常入表，unregister 清账无残留。
"""
from unittest import TestCase

from app.modules.filemanager import FileManagerModule, storage_registry
from app.modules.filemanager.storages import StorageBase
from app.modules.filemanager.storages.local import LocalStorage


class _NonStorage:
    pass


class _IncompleteStorage(StorageBase):
    """未实现 StorageBase 抽象方法 → 不可实例化（__abstractmethods__ 非空）。"""
    pass


class _NoSchemaStorage(LocalStorage):
    """继承完整实现但 schema 置空 → 仅 schema 校验失败。"""
    schema = None


class TestVerifyStorageContract(TestCase):
    def test_valid_storage_passes(self):
        ok, reasons = FileManagerModule.verify_storage_contract(LocalStorage)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])

    def test_non_storagebase_rejected(self):
        ok, reasons = FileManagerModule.verify_storage_contract(_NonStorage)
        self.assertFalse(ok)
        self.assertTrue(any("StorageBase" in r for r in reasons))

    def test_incomplete_abstract_rejected(self):
        ok, reasons = FileManagerModule.verify_storage_contract(_IncompleteStorage)
        self.assertFalse(ok)
        self.assertTrue(any("抽象方法" in r for r in reasons))

    def test_missing_schema_rejected(self):
        ok, reasons = FileManagerModule.verify_storage_contract(_NoSchemaStorage)
        self.assertFalse(ok)
        self.assertTrue(any("schema" in r for r in reasons))

    def test_non_class_rejected(self):
        ok, reasons = FileManagerModule.verify_storage_contract(object())
        self.assertFalse(ok)
        self.assertTrue(reasons)


class TestRegisterStorageGate(TestCase):
    def setUp(self):
        self.owner = "test_storage_owner"

    def tearDown(self):
        FileManagerModule.unregister_storages(self.owner)

    def test_valid_storage_registers(self):
        accepted = FileManagerModule.register_storage(LocalStorage, self.owner)
        self.assertTrue(accepted)
        self.assertIn(LocalStorage, storage_registry.all_storages())

    def test_invalid_storage_rejected_not_in_registry(self):
        accepted = FileManagerModule.register_storage(_IncompleteStorage, self.owner)
        self.assertFalse(accepted)
        self.assertNotIn(_IncompleteStorage, storage_registry.all_storages())
