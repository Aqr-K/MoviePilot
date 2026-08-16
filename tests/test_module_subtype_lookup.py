"""模块按子类型精确查找。

子类型的书写形式有两种：内建模块声明枚举成员，外部注册的模块只能声明字符串。
调用方手上拿到的往往也是字符串（如 ``FileItem.storage``），因此两种形式必须互认，
否则外部注册的模块永远选不中。

两侧都是枚举时按成员身份判定，不降级为取值比较，避免不同枚举的同名取值互相误配。
"""
import threading
from enum import Enum

import pytest

from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.types import MediaServerType, StorageSchema


class SubtypeModule:
    """声明子类型的模块替身"""

    def __init__(self, subtype, name: str = "模块"):
        """
        :param subtype: 模块声明的子类型
        :param name: 模块名称
        """
        self._subtype = subtype
        self._name = name

    def get_subtype(self):
        """模块子类型"""
        return self._subtype

    def get_name(self) -> str:
        """模块名称"""
        return self._name


class BrokenSubtypeModule:
    """取子类型时抛错的模块替身"""

    def get_subtype(self):
        """模块子类型"""
        raise RuntimeError("子类型不可用")


class NoSubtypeModule:
    """未声明子类型的模块替身"""

    def get_name(self) -> str:
        """模块名称"""
        return "无子类型模块"


def make_manager(*modules) -> ModuleManager:
    """
    构造与全局单例隔离、预置运行态模块的模块管理器

    :param modules: 运行态模块替身
    :return: 模块管理器
    """
    manager = object.__new__(ModuleManager)
    manager._modules = {}
    manager._running_modules = {f"module{index}": module for index, module in enumerate(modules)}
    manager._external_classes = {}
    manager._lock = threading.RLock()
    return manager


def lookup(manager: ModuleManager, subtype) -> list:
    """
    按子类型取模块列表

    :param manager: 模块管理器
    :param subtype: 待匹配的子类型
    :return: 命中的模块列表
    """
    return list(manager.get_running_subtype_module(subtype))


def test_enum_query_matches_an_enum_declaration():
    """枚举查枚举命中。"""
    module = SubtypeModule(StorageSchema.Local)

    assert lookup(make_manager(module), StorageSchema.Local) == [module]


def test_string_query_matches_an_enum_declaration():
    """字符串查枚举命中，这是调用方拿着 FileItem.storage 时的形态。"""
    module = SubtypeModule(StorageSchema.Local)

    assert lookup(make_manager(module), "local") == [module]


def test_enum_query_matches_a_string_declaration():
    """枚举查字符串命中，外部模块只能声明字符串子类型。"""
    module = SubtypeModule("local")

    assert lookup(make_manager(module), StorageSchema.Local) == [module]


def test_string_query_matches_a_string_declaration():
    """字符串查字符串命中，这是外部注册存储的常态。"""
    module = SubtypeModule("plugin_cloud")

    assert lookup(make_manager(module), "plugin_cloud") == [module]


def test_a_different_subtype_is_not_matched():
    """子类型不同的模块不被选中。"""
    manager = make_manager(SubtypeModule(StorageSchema.Local), SubtypeModule(StorageSchema.Alipan))

    assert [module.get_subtype() for module in lookup(manager, StorageSchema.Alipan)] \
           == [StorageSchema.Alipan]


def test_same_value_in_a_different_enum_is_not_matched():
    """不同枚举的同名取值不互相误配。"""

    class Foreign(Enum):
        """与存储取值相同的无关枚举"""
        Local = "local"

    manager = make_manager(SubtypeModule(Foreign.Local))

    assert lookup(manager, StorageSchema.Local) == []


def test_cross_family_query_does_not_match():
    """跨家族查询不命中。"""
    manager = make_manager(SubtypeModule(StorageSchema.Local))

    assert lookup(manager, MediaServerType.Emby) == []


def test_a_module_without_a_subtype_is_skipped():
    """未声明子类型的模块被跳过，不影响其余模块。"""
    module = SubtypeModule(StorageSchema.Local)
    manager = make_manager(NoSubtypeModule(), module)

    assert lookup(manager, StorageSchema.Local) == [module]


def test_a_failing_subtype_probe_does_not_break_the_lookup():
    """单个模块取子类型抛错时只跳过该模块，其余模块照常匹配。"""
    module = SubtypeModule(StorageSchema.Local)
    manager = make_manager(BrokenSubtypeModule(), module)

    assert lookup(manager, StorageSchema.Local) == [module]


@pytest.mark.parametrize("empty", [None, ""])
def test_an_empty_query_matches_nothing(empty):
    """查询值为空时不返回任何模块，避免误命中未声明子类型的模块。"""
    manager = make_manager(SubtypeModule(StorageSchema.Local), NoSubtypeModule())

    assert lookup(manager, empty) == []
