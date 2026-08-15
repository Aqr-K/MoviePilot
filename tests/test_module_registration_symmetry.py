"""插件注册模块时的冲突判定对称性。

默认实例的模块标识退化为裸类名，非默认实例追加实例键。限定只用于在同一插件内部消歧，
不能让同一份声明因为实例名不同而得到相反的结论：与内建模块或其它插件重名的声明，来自
默认实例被拒时，来自分身也要被拒，否则分身的模块会独自参与 run_module 广播。
"""
from typing import Optional, Tuple
from unittest.mock import patch

import pytest

from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager, ProvidedModule
from app.schemas.types import ModuleType

PLUGIN_ID = "SymmetryPlugin"
ALPHA_KEY = f"{PLUGIN_ID}@alpha"
OTHER_PLUGIN_ID = "OtherSymmetryPlugin"
OTHER_ALPHA_KEY = f"{OTHER_PLUGIN_ID}@alpha"


class _StubModule(_ModuleBase):
    """满足模块契约的最小实现。"""

    def init_module(self) -> None:
        pass

    def init_setting(self) -> Optional[Tuple[str, bool]]:
        return None

    def stop(self) -> None:
        pass

    def test(self) -> Optional[Tuple[bool, str]]:
        return True, ""

    @staticmethod
    def get_name() -> str:
        return "Stub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Other

    @staticmethod
    def get_subtype():
        return None

    @staticmethod
    def get_priority() -> int:
        return 0

    def stub_capability(self) -> str:
        return "registered"


class BuiltinNamesake(_StubModule):
    """与内建模块同名的插件模块，模块标识取类名。"""


@pytest.fixture
def module_manager():
    """构造与全局单例隔离、只装载一个内建模块的模块管理器。"""
    previous = contract._module_base
    contract.configure_module_base(_ModuleBase)
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load",
               return_value=[BuiltinNamesake]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    yield instance
    contract._module_base = previous


def test_default_instance_is_rejected_when_a_builtin_module_owns_the_name(module_manager):
    """与内建模块重名的声明来自默认实例时被拒。"""
    assert module_manager.register_module(BuiltinNamesake, owner=PLUGIN_ID) is False
    assert module_manager.get_external_module_ids(PLUGIN_ID) == []


def test_alias_instance_is_rejected_on_the_same_builtin_name(module_manager):
    """同一份声明来自分身实例时同样被拒，不得因为实例键限定而绕过。"""
    assert module_manager.register_module(BuiltinNamesake, owner=ALPHA_KEY) is False
    assert module_manager.get_external_module_ids(ALPHA_KEY) == []
    assert len(list(module_manager.get_running_modules("stub_capability"))) == 1


def test_alias_instance_is_rejected_when_another_plugin_owns_the_name(module_manager):
    """模块标识已被其它插件占用时，分身实例的声明同样被拒。"""
    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="shared"), owner=OTHER_PLUGIN_ID
    ) is True

    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="shared"), owner=ALPHA_KEY
    ) is False
    assert module_manager.get_external_module_ids(ALPHA_KEY) == []


def test_default_instance_is_rejected_when_another_plugin_owns_the_name(module_manager):
    """同样的占用对默认实例给出相同结论。"""
    module_manager.register_module(
        ProvidedModule(_StubModule, module_id="shared"), owner=OTHER_PLUGIN_ID
    )

    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="shared"), owner=PLUGIN_ID
    ) is False


def test_instances_of_one_plugin_still_share_a_module_id(module_manager):
    """同一插件的多个实例注册同一模块类仍各自上线，限定只在插件内部消歧。"""
    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="own"), owner=PLUGIN_ID
    ) is True
    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="own"), owner=ALPHA_KEY
    ) is True

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["own"]
    assert module_manager.get_external_module_ids(ALPHA_KEY) == [f"own@{ALPHA_KEY}"]


def test_two_alias_instances_of_different_plugins_do_not_collide(module_manager):
    """不同插件的分身各自限定后互不重名，双方都被接受。"""
    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="alias"), owner=ALPHA_KEY
    ) is True
    assert module_manager.register_module(
        ProvidedModule(_StubModule, module_id="alias"), owner=OTHER_ALPHA_KEY
    ) is True
