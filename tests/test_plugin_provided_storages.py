"""插件注册式存储驱动：注册表契约、重名判定与文件整理模块的合并视图。"""
from pathlib import Path
from typing import List, Optional
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.adapters.storage import StorageBase
from app.adapters.storage import registry
from app.adapters.storage.registry import (
    configure_builtin_schemas,
    get_registered_storages,
    register_storage,
    storage_schema_value,
    unregister_storages,
)
from app.application.directory import _split_file_uri
from app.modules.filemanager import FileManagerModule
from app.schemas.file import FileURI, configure_storage_schema_provider
from app.schemas.types import StorageSchema


class StubStorage(StorageBase):
    """满足存储契约的最小实现"""

    transtype = {"copy": "复制"}

    def init_storage(self):
        self.init_calls = getattr(self, "init_calls", 0) + 1

    def check(self) -> bool:
        return True

    def list(self, fileitem: schemas.FileItem) -> List[schemas.FileItem]:
        return []

    def create_folder(self, fileitem: schemas.FileItem, name: str) -> Optional[schemas.FileItem]:
        return None

    def get_folder(self, path: Path) -> Optional[schemas.FileItem]:
        return None

    def get_item(self, path: Path) -> Optional[schemas.FileItem]:
        return None

    def delete(self, fileitem: schemas.FileItem) -> bool:
        return True

    def rename(self, fileitem: schemas.FileItem, name: str) -> bool:
        return True

    def download(self, fileitem: schemas.FileItem, path: Path = None) -> Optional[Path]:
        return None

    def upload(self, fileitem: schemas.FileItem, path: Path,
               new_name: Optional[str] = None) -> Optional[schemas.FileItem]:
        return None

    def detail(self, fileitem: schemas.FileItem) -> Optional[schemas.FileItem]:
        return None

    def copy(self, fileitem: schemas.FileItem, path: Path, new_name: str) -> bool:
        return True

    def move(self, fileitem: schemas.FileItem, path: Path, new_name: str) -> bool:
        return True

    def link(self, fileitem: schemas.FileItem, target_file: Path) -> bool:
        return True

    def softlink(self, fileitem: schemas.FileItem, target_file: Path) -> bool:
        return True

    def usage(self) -> Optional[schemas.StorageUsage]:
        return None


class BuiltinStubStorage(StubStorage):
    """内建存储替身，schema 取自封闭枚举"""

    schema = StorageSchema.Local


class PluginStorage(StubStorage):
    """插件声明的存储，schema 为普通字符串"""

    schema = "plugin_cloud"
    transtype = {"move": "移动"}


class RivalPluginStorage(StubStorage):
    """另一个插件声明的同名存储"""

    schema = "plugin_cloud"


class ShadowLocalStorage(StubStorage):
    """与内建存储同名的插件存储"""

    schema = "local"


class SchemalessStorage(StubStorage):
    """未声明 schema 的存储"""

    schema = ""


class NotAStorage:
    """未继承存储基类的候选类"""

    schema = "fake_cloud"


class AbstractStorage(StorageBase):
    """未落地抽象方法的存储"""

    schema = "abstract_cloud"


@pytest.fixture(autouse=True)
def clean_registry():
    """清空存储注册表、内建标识与 URI 标识来源，隔离用例间的全局状态。"""
    def purge():
        """把三处全局状态复位到未装配"""
        registry._registered.clear()
        configure_builtin_schemas([])
        configure_storage_schema_provider(None)

    purge()
    yield
    purge()


@pytest.fixture
def filemanager() -> FileManagerModule:
    """构造只识别 BuiltinStubStorage 一个内建存储的文件整理模块。"""
    module = FileManagerModule()
    with patch("app.modules.filemanager.ModuleHelper.load", return_value=[BuiltinStubStorage]):
        module.init_module()
    return module


def storage_oper(module: FileManagerModule, storage: str) -> Optional[StorageBase]:
    """按存储标识取文件整理模块内部的存储操作对象。"""
    return module._FileManagerModule__get_storage_oper(storage)  # noqa: SLF001


# --------------------------------------------------------------------------- schema 解析


def test_schema_value_reads_enum_string_and_others():
    """枚举成员取 value，字符串原样返回，其余为空。"""
    assert storage_schema_value(BuiltinStubStorage) == "local"
    assert storage_schema_value(PluginStorage) == "plugin_cloud"
    assert storage_schema_value(PluginStorage()) == "plugin_cloud"
    assert storage_schema_value(SchemalessStorage) is None
    assert storage_schema_value(object()) is None


# --------------------------------------------------------------------------- 注册面


def test_registered_storage_joins_the_file_manager_view(filemanager):
    """注册成功的存储应进入支持列表并可取到操作对象。"""
    assert register_storage(PluginStorage, owner="plugin_a") is True

    assert "plugin_cloud" in filemanager._support_storages()
    assert isinstance(storage_oper(filemanager, "plugin_cloud"), PluginStorage)
    assert filemanager.support_transtype("plugin_cloud") == {"move": "移动"}


def test_storage_registered_after_init_module_is_visible():
    """插件晚于模块初始化注册的存储同样应能被取到。"""
    module = FileManagerModule()
    with patch("app.modules.filemanager.ModuleHelper.load", return_value=[BuiltinStubStorage]):
        module.init_module()

    assert storage_oper(module, "plugin_cloud") is None

    register_storage(PluginStorage, owner="plugin_a")

    assert "plugin_cloud" in module._support_storages()
    assert isinstance(storage_oper(module, "plugin_cloud"), PluginStorage)


def test_register_rejects_a_schema_taken_by_a_builtin_storage(filemanager):
    """与内建存储重名的注册应被拒绝，内建实现不被顶替。"""
    assert register_storage(ShadowLocalStorage, owner="plugin_a") is False

    assert get_registered_storages() == []
    assert isinstance(storage_oper(filemanager, "local"), BuiltinStubStorage)


def test_register_rejects_a_schema_taken_by_another_owner(filemanager):
    """同名 schema 先到者胜，后到的其它来源被拒绝。"""
    assert register_storage(PluginStorage, owner="plugin_a") is True
    assert register_storage(RivalPluginStorage, owner="plugin_b") is False

    assert get_registered_storages() == [PluginStorage]
    assert isinstance(storage_oper(filemanager, "plugin_cloud"), PluginStorage)


def test_register_is_idempotent_for_the_same_owner(filemanager):
    """同一来源重复注册同一存储不产生重复条目。"""
    assert register_storage(PluginStorage, owner="plugin_a") is True
    assert register_storage(PluginStorage, owner="plugin_a") is True

    assert get_registered_storages() == [PluginStorage]
    assert filemanager._support_storages().count("plugin_cloud") == 1


def test_register_rejects_candidates_outside_the_storage_base():
    """未继承存储基类或未声明 schema 的候选类应被拒绝。"""
    assert register_storage(NotAStorage, owner="plugin_a") is False
    assert register_storage(SchemalessStorage, owner="plugin_a") is False
    assert register_storage(PluginStorage(), owner="plugin_a") is False
    assert register_storage(PluginStorage, owner="") is False

    assert get_registered_storages() == []


def test_register_rejects_a_storage_with_unimplemented_abstract_methods():
    """抽象方法未落地的存储在注册阶段就被拒绝，而不是等到取用时才实例化失败。"""
    assert register_storage(AbstractStorage, owner="plugin_a") is False

    assert get_registered_storages() == []


def test_unregister_removes_the_storage_from_the_file_manager_view(filemanager):
    """按来源卸载后该存储应从支持列表和取用路径中消失。"""
    register_storage(PluginStorage, owner="plugin_a")

    assert unregister_storages("plugin_a") == ["plugin_cloud"]

    assert get_registered_storages() == []
    assert "plugin_cloud" not in filemanager._support_storages()
    assert storage_oper(filemanager, "plugin_cloud") is None
    assert isinstance(storage_oper(filemanager, "local"), BuiltinStubStorage)


def test_unregister_keeps_storages_of_other_owners(filemanager):
    """卸载一个来源不应影响其它来源注册的存储。"""
    register_storage(PluginStorage, owner="plugin_a")

    assert unregister_storages("plugin_b") == []

    assert get_registered_storages() == [PluginStorage]


# --------------------------------------------------------------------------- 配置读写


def test_string_schema_storage_reads_and_writes_its_config():
    """schema 为普通字符串的存储应能按标识读写和重置配置。"""
    storage = PluginStorage()
    storage.storagehelper = Mock()
    storage.storagehelper.get_storage.return_value = schemas.StorageConf(
        type="plugin_cloud", name="插件云盘", config={"token": "old"}
    )

    conf = storage.get_config()
    storage.set_config({"token": "new"})
    storage.reset_config()

    assert conf.config == {"token": "old"}
    storage.storagehelper.get_storage.assert_called_once_with("plugin_cloud")
    storage.storagehelper.set_storage.assert_called_once_with("plugin_cloud", {"token": "new"})
    storage.storagehelper.reset_storage.assert_called_once_with("plugin_cloud")


def test_enum_schema_storage_keeps_using_the_enum_value():
    """schema 为枚举成员的存储仍按枚举值读写配置。"""
    storage = BuiltinStubStorage()
    storage.storagehelper = Mock()
    storage.storagehelper.get_storage.return_value = None

    storage.get_config()
    storage.set_config({"path": "/media"})
    storage.reset_config()

    storage.storagehelper.get_storage.assert_called_once_with("local")
    storage.storagehelper.set_storage.assert_called_once_with("local", {"path": "/media"})
    storage.storagehelper.reset_storage.assert_called_once_with("local")


def test_registered_storage_uri_round_trips(filemanager):
    """外部注册存储的路径能按其 schema 前缀解析回来，而不是退化成本地路径。"""
    register_storage(PluginStorage, owner="plugin_a")

    parsed = FileURI.from_uri("plugin_cloud:/media/movie")

    assert parsed.storage == "plugin_cloud"
    assert parsed.path == "/media/movie"
    assert parsed.uri == "plugin_cloud:/media/movie"


def test_registered_storage_directory_uri_round_trips(filemanager):
    """目录配置里的外部存储前缀同样能被拆分出来。"""
    register_storage(PluginStorage, owner="plugin_a")

    assert _split_file_uri("plugin_cloud:/downloads") == ("plugin_cloud", "/downloads")


def test_unregistered_storage_prefix_is_not_recognized(filemanager):
    """存储卸载后其前缀不再被识别，路径回到本地解析。"""
    register_storage(PluginStorage, owner="plugin_a")
    unregister_storages("plugin_a")

    assert FileURI.from_uri("plugin_cloud:/media").storage == "local"


def test_uri_parsing_falls_back_to_builtin_schemas_without_a_provider():
    """未装配外部标识来源时只认内建存储，解析行为保持不变。"""
    configure_storage_schema_provider(None)

    assert FileURI.from_uri("u115:/media").storage == "u115"
    assert FileURI.from_uri("plugin_cloud:/media").storage == "local"
