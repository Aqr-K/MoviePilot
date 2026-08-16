"""内建存储作为一级模块参与精确分发。

7 个内建存储与媒体服务器、下载器同级，各自以自己的存储标识作为模块子类型；存储链按
标识精确选中一个模块，兄弟存储一个都不被调用——否则一次删除会打到所有存储上。
"""
import threading
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.chain.storage import StorageChain
from app.modules.storages import AliPan, Alist, AlistGo, LocalStorage, Rclone, SMB, U115Pan
from app.modules.storages.base import StorageBase
from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.types import ModuleType, StorageSchema

BUILTIN_STORAGES = (LocalStorage, AliPan, U115Pan, Rclone, Alist, AlistGo, SMB)


@pytest.fixture
def manager() -> ModuleManager:
    """构造与全局单例隔离、只装载 7 个内建存储的模块管理器。"""
    instance = object.__new__(ModuleManager)
    instance._modules = {}
    instance._running_modules = {}
    instance._external_classes = {}
    instance._lock = threading.RLock()
    helper = Mock(get_storage=Mock(return_value=None))
    with patch("app.modules.storages.base.StorageHelper", return_value=helper):
        for storage_cls in BUILTIN_STORAGES:
            module = storage_cls()
            module.storagehelper = helper
            instance._modules[storage_cls.__name__] = storage_cls
            instance._running_modules[storage_cls.__name__] = module
    return instance


@pytest.fixture
def chain(manager: ModuleManager) -> StorageChain:
    """构造只认上述模块管理器的存储链。"""
    instance = StorageChain()
    instance.modulemanager = manager
    instance.pluginmanager = Mock(running_plugins={})
    instance.messagehelper = Mock()
    instance.eventmanager = Mock()
    return instance


def test_every_builtin_storage_declares_the_storage_module_type():
    """7 个内建存储都声明为存储类型的模块。"""
    assert {storage.get_type() for storage in BUILTIN_STORAGES} == {ModuleType.Storage}


def test_every_storage_schema_has_a_module():
    """每个内建存储标识都有对应模块，清单与枚举一一对应。"""
    declared = {storage.get_subtype() for storage in BUILTIN_STORAGES}

    assert declared == set(StorageSchema)


def test_storage_modules_satisfy_the_module_contract():
    """存储模块满足模块契约，可被外部注册路径接受。"""
    for storage in BUILTIN_STORAGES:
        assert issubclass(storage, StorageBase)
        assert not getattr(storage, "__abstractmethods__", frozenset())


def test_the_running_storage_list_covers_every_schema(manager):
    """运行态存储清单覆盖全部存储标识。"""
    assert sorted(manager.get_running_subtypes(ModuleType.Storage)) \
           == sorted(schema.value for schema in StorageSchema)


@pytest.mark.parametrize("schema, expected", [
    (StorageSchema.Local.value, LocalStorage),
    (StorageSchema.Alipan.value, AliPan),
    (StorageSchema.U115.value, U115Pan),
    (StorageSchema.Rclone.value, Rclone),
    (StorageSchema.Alist.value, Alist),
    (StorageSchema.AlistGo.value, AlistGo),
    (StorageSchema.SMB.value, SMB),
])
def test_each_schema_resolves_to_its_own_module(manager, schema, expected):
    """每个存储标识精确解析到自己的模块。"""
    resolved = list(manager.get_running_subtype_module(schema))

    assert [type(module) for module in resolved] == [expected]


def test_deleting_a_file_reaches_only_the_owning_storage(chain, manager):
    """一次删除只打到文件所属的存储，其余 6 个存储一个都不被调用。"""
    calls = []
    for module_id, module in manager._running_modules.items():
        module.delete = lambda fileitem, _id=module_id: calls.append(_id) or True

    result = chain.delete_file(
        schemas.FileItem(storage=StorageSchema.Alipan.value, path="/x.mkv", type="file"))

    assert result is True
    assert calls == ["AliPan"]


def test_an_unknown_storage_reaches_nothing(chain, manager):
    """未知存储标识不命中任何模块，也不回落到广播。"""
    calls = []
    for module_id, module in manager._running_modules.items():
        module.delete = lambda fileitem, _id=module_id: calls.append(_id) or True

    result = chain.delete_file(
        schemas.FileItem(storage="nope", path="/x.mkv", type="file"))

    assert result is None
    assert calls == []


def test_listing_files_recurses_over_single_level_listings(chain, manager):
    """递归遍历由存储链完成，驱动只需提供单层列举。"""
    root = schemas.FileItem(storage=StorageSchema.Local.value, path="/root", type="dir")
    child = schemas.FileItem(storage=StorageSchema.Local.value, path="/root/sub", type="dir")
    leaf = schemas.FileItem(storage=StorageSchema.Local.value, path="/root/sub/a.mkv",
                            type="file", extension="mkv")
    listings = {"/root": [child], "/root/sub": [leaf]}
    manager._running_modules["LocalStorage"].list = lambda fileitem: listings.get(fileitem.path, [])

    assert chain.list_files(root, recursion=True) == [leaf]
    assert chain.list_files(root) == [child]


def test_listing_an_unavailable_storage_returns_none(chain):
    """存储不可用时列举返回 None，与可用但为空区分开。"""
    absent = schemas.FileItem(storage="nope", path="/root", type="dir")

    assert chain.list_files(absent) is None


def test_any_files_matches_by_extension_across_levels(chain, manager):
    """按扩展名递归判定文件存在，跨层级生效。"""
    root = schemas.FileItem(storage=StorageSchema.Local.value, path="/root", type="dir")
    child = schemas.FileItem(storage=StorageSchema.Local.value, path="/root/sub", type="dir")
    leaf = schemas.FileItem(storage=StorageSchema.Local.value, path="/root/sub/a.mkv",
                            type="file", extension="mkv")
    listings = {"/root": [child], "/root/sub": [leaf]}
    manager._running_modules["LocalStorage"].list = lambda fileitem: listings.get(fileitem.path, [])

    assert chain.any_files(root, extensions=[".mkv"]) is True
    assert chain.any_files(root, extensions=[".iso"]) is False
