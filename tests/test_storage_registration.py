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


class _FakeSchema:
    """模拟插件自定义存储类型身份（schema.value 为枚举外字符串 id）。"""

    def __init__(self, value):
        self.value = value

    def __bool__(self):
        return True


class _PluginCloudStorage(LocalStorage):
    """合法插件存储器：继承完整实现，schema.value 为新字符串（非内建）。"""
    schema = _FakeSchema("testcloud")


class _PluginCloudStorage2(LocalStorage):
    """与 _PluginCloudStorage 同 schema.value，用于跨 owner 碰撞验证。"""
    schema = _FakeSchema("testcloud")


class _DupLocalStorage(LocalStorage):
    """继承 schema=StorageSchema.Local → 与内建 'local' 碰撞。"""
    pass


class _RegGateStorage(LocalStorage):
    """TestRegisterStorageGate 专用、独立 schema.value，避免与碰撞测试争用同一索引键。"""
    schema = _FakeSchema("reggate")


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
        # 用非内建、且专属本类的 schema.value 插件存储（避免与碰撞测试争用 'testcloud' 键）
        accepted = FileManagerModule.register_storage(_RegGateStorage, self.owner)
        self.assertTrue(accepted)
        self.assertIn(_RegGateStorage, storage_registry.all_storages())

    def test_invalid_storage_rejected_not_in_registry(self):
        accepted = FileManagerModule.register_storage(_IncompleteStorage, self.owner)
        self.assertFalse(accepted)
        self.assertNotIn(_IncompleteStorage, storage_registry.all_storages())


class TestStorageSchemaCollision(TestCase):
    """schema.value 碰撞检测：与内建/他 owner 冲突即拒，同 owner 幂等放行。"""

    def tearDown(self):
        for o in ("own_a", "own_b", "own_dup"):
            FileManagerModule.unregister_storages(o)

    def test_builtin_schema_collision_rejected(self):
        # 插件存储 schema.value 撞内建 'local' → 拒绝，避免遮蔽内建路由
        accepted = FileManagerModule.register_storage(_DupLocalStorage, "own_dup")
        self.assertFalse(accepted)
        self.assertNotIn(_DupLocalStorage, storage_registry.all_storages())

    def test_cross_owner_schema_collision_rejected(self):
        self.assertTrue(FileManagerModule.register_storage(_PluginCloudStorage, "own_a"))
        # 另一 owner 用相同 schema.value 注册 → 拒绝
        self.assertFalse(FileManagerModule.register_storage(_PluginCloudStorage2, "own_b"))
        self.assertNotIn(_PluginCloudStorage2, storage_registry.all_storages())

    def test_same_owner_reregister_idempotent(self):
        self.assertTrue(FileManagerModule.register_storage(_PluginCloudStorage, "own_a"))
        # 同 owner 再次注册同类 → 幂等放行（不误判为冲突）
        self.assertTrue(FileManagerModule.register_storage(_PluginCloudStorage, "own_a"))
        self.assertIn(_PluginCloudStorage, storage_registry.all_storages())
