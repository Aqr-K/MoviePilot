"""内建独占能力：外部来源不得提供站点索引。

站点索引是刻意不开放给插件的能力面。此前这条约束只存在于「没有给 indexer 做注册器」这个
事实上，而 indexer 是不是注册器根本不决定结果——``provides_modules()`` 的契约是「注册后
与内建模块同权参与分发」，任何插件模块只要实现 ``search_torrents``，就会进入
``run_module("search_torrents", ...)`` 的广播，绕过 indexer 直接供种。

因此约束要落在能力面上：这批能力只接受内建模块提供，外部来源的注册一律拒绝。
"""
import threading
from typing import Optional, Tuple

import pytest

from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.capability import BUILTIN_ONLY_CAPABILITIES
from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.types import ModuleType


class StubModule(_ModuleBase):
    """满足模块契约的最小实现"""

    def init_module(self) -> None:
        """模块初始化"""

    def init_setting(self) -> Optional[Tuple[str, bool]]:
        """模块开关"""
        return None

    def stop(self) -> None:
        """停止模块"""

    def test(self) -> Optional[Tuple[bool, str]]:
        """模块测试"""
        return True, ""

    @staticmethod
    def get_name() -> str:
        """模块名称"""
        return "Stub"

    @staticmethod
    def get_type() -> ModuleType:
        """模块类型"""
        return ModuleType.Other

    @staticmethod
    def get_subtype():
        """模块子类型"""
        return None

    @staticmethod
    def get_priority() -> int:
        """模块优先级"""
        return 0


def module_with(capability: str) -> type:
    """
    构造提供指定能力的模块类

    :param capability: 能力方法名
    :return: 模块类
    """
    return type(f"Provides{capability.title().replace('_', '')}", (StubModule,),
                {capability: lambda self, *args, **kwargs: ["result"]})


@pytest.fixture(autouse=True)
def module_base():
    """把模块基类装配到契约校验层。"""
    previous = contract._module_base  # noqa: SLF001
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous  # noqa: SLF001


@pytest.fixture
def manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    instance._modules = {}  # noqa: SLF001
    instance._running_modules = {}  # noqa: SLF001
    instance._external_classes = {}  # noqa: SLF001
    instance._lock = threading.RLock()  # noqa: SLF001
    return instance


def test_the_indexing_capabilities_are_reserved():
    """站点索引的能力面在内建独占清单里。"""
    assert {"search_torrents", "refresh_torrents", "refresh_userdata",
            "search_subtitles", "get_search_page_size"} <= BUILTIN_ONLY_CAPABILITIES


@pytest.mark.parametrize("capability", sorted(BUILTIN_ONLY_CAPABILITIES))
def test_an_external_module_providing_a_reserved_capability_is_rejected(manager, capability):
    """外部来源提供内建独占能力时拒绝注册。"""
    assert manager.register_module(module_with(capability), owner="EvilPlugin") is False

    assert manager.get_external_module_ids() == []


def test_a_rejected_module_never_reaches_the_broadcast(manager):
    """被拒的模块不出现在广播集合里，插件无法绕过 indexer 供种。"""
    manager.register_module(module_with("search_torrents"), owner="EvilPlugin")

    reachable = [type(module).__name__ for module in manager.get_running_modules("search_torrents")]

    assert reachable == []


def test_an_ordinary_external_module_is_still_accepted(manager):
    """不涉及独占能力的外部模块照常注册，限制不外溢。"""
    assert manager.register_module(module_with("post_message"), owner="GoodPlugin") is True

    assert manager.get_external_module_ids("GoodPlugin") != []
