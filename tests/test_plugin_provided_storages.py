"""插件注册式存储驱动：模块契约、存储类型占用判定与精确分发的可达性。

存储是系统模块的一种，经模块管理器注册，按存储类型精确分发。同一存储类型只能有一个
模块在运行，否则外部来源可以静默顶替内建后端。
"""
from pathlib import Path
from typing import List, Optional
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.application.directory import _split_file_uri
from app.modules import _ModuleBase
from app.modules.storages.base import StorageBase
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager, subtype_value
from app.schemas.file import FileURI, configure_storage_schema_provider
from app.schemas.types import ModuleType, StorageSchema


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
def clean_provider():
    """把 URI 标识来源复位到未装配，隔离用例间的全局状态。"""
    configure_storage_schema_provider(None)
    yield
    configure_storage_schema_provider(None)


@pytest.fixture(autouse=True)
def module_base():
    """把模块基类装配到契约校验层，使外部声明的存储可被判定。"""
    previous = contract._module_base  # noqa: SLF001
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous  # noqa: SLF001


@pytest.fixture
def manager() -> ModuleManager:
    """构造只装载 BuiltinStubStorage 一个内建存储的模块管理器，并接上标识来源。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load",
               return_value=[BuiltinStubStorage]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    configure_storage_schema_provider(
        lambda: instance.get_running_subtypes(ModuleType.Storage))
    return instance


def storage_oper(manager: ModuleManager, storage: str) -> Optional[StorageBase]:
    """按存储标识取精确分发命中的存储模块实例。"""
    return next(iter(manager.get_running_subtype_module(storage)), None)


# --------------------------------------------------------------------------- schema 解析


def test_subtype_value_reads_enum_string_and_others():
    """枚举成员取 value，字符串原样返回，其余为空。"""
    assert subtype_value(BuiltinStubStorage.get_subtype()) == "local"
    assert subtype_value(PluginStorage.get_subtype()) == "plugin_cloud"
    assert subtype_value(PluginStorage().get_subtype()) == "plugin_cloud"
    assert subtype_value(SchemalessStorage.get_subtype()) is None
    assert subtype_value(object()) is None


# --------------------------------------------------------------------------- 注册面


def test_registered_storage_becomes_reachable(manager):
    """注册成功的存储进入运行态，可按存储标识精确命中。"""
    assert manager.register_module(PluginStorage, owner="plugin_a") is True

    assert "plugin_cloud" in manager.get_running_subtypes(ModuleType.Storage)
    assert isinstance(storage_oper(manager, "plugin_cloud"), PluginStorage)
    assert storage_oper(manager, "plugin_cloud").support_transtype() == {"move": "移动"}


def test_storage_registered_after_startup_is_visible(manager):
    """插件晚于模块装载注册的存储同样能被命中。"""
    assert storage_oper(manager, "plugin_cloud") is None

    manager.register_module(PluginStorage, owner="plugin_a")

    assert "plugin_cloud" in manager.get_running_subtypes(ModuleType.Storage)
    assert isinstance(storage_oper(manager, "plugin_cloud"), PluginStorage)


def test_register_rejects_a_schema_taken_by_a_builtin_storage(manager):
    """与内建存储重名的注册被拒绝，内建实现不被顶替。"""
    assert manager.register_module(ShadowLocalStorage, owner="plugin_a") is False

    assert manager.get_external_module_ids() == []
    assert isinstance(storage_oper(manager, "local"), BuiltinStubStorage)


def test_register_rejects_a_schema_taken_by_another_owner(manager):
    """同一存储类型先到者胜，后到的其它来源被拒绝。"""
    assert manager.register_module(PluginStorage, owner="plugin_a") is True
    assert manager.register_module(RivalPluginStorage, owner="plugin_b") is False

    assert manager.get_external_module_ids() == ["PluginStorage"]
    assert isinstance(storage_oper(manager, "plugin_cloud"), PluginStorage)


def test_register_is_idempotent_for_the_same_owner(manager):
    """同一来源重复注册同一存储不产生重复条目。"""
    assert manager.register_module(PluginStorage, owner="plugin_a") is True
    assert manager.register_module(PluginStorage, owner="plugin_a") is True

    assert manager.get_external_module_ids() == ["PluginStorage"]
    assert manager.get_running_subtypes(ModuleType.Storage).count("plugin_cloud") == 1


def test_register_rejects_candidates_outside_the_module_contract(manager):
    """未继承模块基类的候选类、实例声明与空来源都被拒绝。"""
    assert manager.register_module(NotAStorage, owner="plugin_a") is False
    assert manager.register_module(PluginStorage(), owner="plugin_a") is False
    assert manager.register_module(PluginStorage, owner="") is False

    assert manager.get_external_module_ids() == []


def test_register_rejects_a_storage_with_unimplemented_abstract_methods(manager):
    """抽象方法未落地的存储在注册阶段就被拒绝，而不是等到取用时才实例化失败。"""
    assert manager.register_module(AbstractStorage, owner="plugin_a") is False

    assert manager.get_external_module_ids() == []


def test_register_rejects_a_storage_without_a_schema(manager):
    """未声明存储类型的存储无法参与精确分发，注册后不出现在存储清单里。"""
    manager.register_module(SchemalessStorage, owner="plugin_a")

    assert manager.get_running_subtypes(ModuleType.Storage) == ["local"]


def test_unregister_removes_the_storage_from_dispatch(manager):
    """按来源卸载后该存储从存储清单与分发路径中消失，内建存储不受影响。"""
    manager.register_module(PluginStorage, owner="plugin_a")

    assert manager.unregister_modules("plugin_a") == ["PluginStorage"]

    assert manager.get_external_module_ids() == []
    assert "plugin_cloud" not in manager.get_running_subtypes(ModuleType.Storage)
    assert storage_oper(manager, "plugin_cloud") is None
    assert isinstance(storage_oper(manager, "local"), BuiltinStubStorage)


def test_unregister_keeps_storages_of_other_owners(manager):
    """卸载一个来源不影响其它来源注册的存储。"""
    manager.register_module(PluginStorage, owner="plugin_a")

    assert manager.unregister_modules("plugin_b") == []

    assert manager.get_external_module_ids() == ["PluginStorage"]


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


def test_registered_storage_uri_round_trips(manager):
    """外部注册存储的路径能按其 schema 前缀解析回来，而不是退化成本地路径。"""
    manager.register_module(PluginStorage, owner="plugin_a")

    parsed = FileURI.from_uri("plugin_cloud:/media/movie")

    assert parsed.storage == "plugin_cloud"
    assert parsed.path == "/media/movie"
    assert parsed.uri == "plugin_cloud:/media/movie"


def test_registered_storage_directory_uri_round_trips(manager):
    """目录配置里的外部存储前缀同样能被拆分出来。"""
    manager.register_module(PluginStorage, owner="plugin_a")

    assert _split_file_uri("plugin_cloud:/downloads") == ("plugin_cloud", "/downloads")


def test_unregistered_storage_prefix_is_not_recognized(manager):
    """存储卸载后其前缀不再被识别，路径回到本地解析。"""
    manager.register_module(PluginStorage, owner="plugin_a")
    manager.unregister_modules("plugin_a")

    assert FileURI.from_uri("plugin_cloud:/media").storage == "local"


def test_uri_parsing_falls_back_to_builtin_schemas_without_a_provider():
    """未装配外部标识来源时只认内建存储，解析行为保持不变。"""
    configure_storage_schema_provider(None)

    assert FileURI.from_uri("u115:/media").storage == "u115"
    assert FileURI.from_uri("plugin_cloud:/media").storage == "local"
