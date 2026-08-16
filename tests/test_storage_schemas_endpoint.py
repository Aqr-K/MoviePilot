"""可用存储类型端点：内建存储与插件声明的存储合并对外呈现。

存储标识来源由启动组合层装配为模块管理器中运行态存储模块的子类型集合。
"""
from pathlib import Path
from typing import List, Optional

from unittest.mock import patch

import pytest

from app import schemas
from app.api.endpoints.storage import storage_schemas
from app.modules.storages.base import StorageBase
from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.file import configure_storage_schema_provider
from app.schemas.types import ModuleType, StorageSchema


class PluginStorage(StorageBase):
    """插件声明的存储，schema 为普通字符串"""

    schema = "plugin_cloud"
    transtype = {"move": "移动"}

    def init_storage(self):
        pass

    def check(self) -> bool:
        return True

    def list(self, fileitem) -> List[schemas.FileItem]:
        return []

    def create_folder(self, fileitem, name: str) -> Optional[schemas.FileItem]:
        return None

    def get_folder(self, path: Path) -> Optional[schemas.FileItem]:
        return None

    def get_item(self, path: Path) -> Optional[schemas.FileItem]:
        return None

    def detail(self, fileitem) -> Optional[schemas.FileItem]:
        return None

    def delete(self, fileitem) -> bool:
        return True

    def rename(self, fileitem, name: str) -> bool:
        return True

    def download(self, fileitem, path: Path = None) -> Optional[Path]:
        return None

    def upload(self, fileitem, path: Path, new_name: Optional[str] = None):
        return None

    def copy(self, fileitem, path: Path, new_name: str) -> bool:
        return True

    def move(self, fileitem, path: Path, new_name: str) -> bool:
        return True

    def link(self, fileitem, target_file: Path) -> bool:
        return True

    def softlink(self, fileitem, target_file: Path) -> bool:
        return True

    def usage(self) -> Optional[schemas.StorageUsage]:
        return None


@pytest.fixture(autouse=True)
def clean_provider():
    """把 URI 标识来源复位到未装配，隔离用例间的全局状态。"""
    configure_storage_schema_provider(None)
    yield
    configure_storage_schema_provider(None)


@pytest.fixture
def module_manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    configure_storage_schema_provider(
        lambda: instance.get_running_subtypes(ModuleType.Storage))
    return instance


def schema_names() -> List[str]:
    """取端点返回的存储标识列表。"""
    return [item.name for item in storage_schemas(None)]


def test_builtin_storages_are_all_listed():
    """内建存储全部出现在清单里，并标记为内建。"""
    listed = {item.name: item.builtin for item in storage_schemas(None)}

    for schema in StorageSchema:
        assert listed[schema.value] is True


def test_a_plugin_storage_joins_the_list_as_non_builtin(module_manager):
    """插件注册的存储进入清单，并标记为非内建。"""
    module_manager.register_module(PluginStorage, owner="plugin_a")

    listed = {item.name: item.builtin for item in storage_schemas(None)}

    assert listed["plugin_cloud"] is False


def test_an_unregistered_plugin_storage_leaves_the_list(module_manager):
    """插件存储卸载后从清单中消失，内建存储不受影响。"""
    module_manager.register_module(PluginStorage, owner="plugin_a")
    module_manager.unregister_modules("plugin_a")

    names = schema_names()

    assert "plugin_cloud" not in names
    assert StorageSchema.Local.value in names


def test_the_list_falls_back_to_builtin_storages_without_a_provider():
    """未装配外部标识来源时只列内建存储。"""
    assert schema_names() == [schema.value for schema in StorageSchema]


def test_listed_names_are_unique(module_manager):
    """清单不出现重复标识。"""
    module_manager.register_module(PluginStorage, owner="plugin_a")

    names = schema_names()

    assert len(names) == len(set(names))
