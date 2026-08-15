"""插件注册式模块 SPI：契约校验、注册面、聚合器与生命周期编排。"""
import threading
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import pytest

from app.modules import _ModuleBase
from app.runtime.deprecation import policy
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager, ProvidedModule
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.extensions.plugin_spi import get_plugin_modules, get_plugin_provided_modules
from app.schemas.types import ModuleType


class StubModule(_ModuleBase):
    """满足模块契约的最小实现"""

    def __init__(self):
        """记录生命周期调用次数"""
        super().__init__()
        self.init_calls = 0
        self.stop_calls = 0

    def init_module(self) -> None:
        self.init_calls += 1

    def init_setting(self) -> Optional[Tuple[str, bool]]:
        return None

    def stop(self) -> None:
        self.stop_calls += 1

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
        """供分发按方法名命中的能力方法"""
        return "registered"


class OtherStubModule(StubModule):
    """与 StubModule 同契约的另一个模块"""

    @staticmethod
    def get_name() -> str:
        return "OtherStub"


class DisabledStubModule(StubModule):
    """开关始终关闭的模块"""

    def init_setting(self) -> Tuple[str, bool]:
        return "NEVER_ENABLED_SWITCH", True


class BrokenModule:
    """未继承模块基类的候选类"""

    def init_module(self) -> None:
        pass

    def init_setting(self):
        return None

    def stop(self) -> None:
        pass

    def test(self):
        return True, ""

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Other

    @staticmethod
    def get_subtype():
        return None


class DemandingModule(StubModule):
    """生命周期方法索取额外必填参数的模块"""

    def init_module(self, extra) -> None:  # noqa: ARG002  用于触发签名校验
        pass


@pytest.fixture(autouse=True)
def module_base_configured():
    """按启动组合根的方式装配模块基类，用例结束后还原。"""
    previous = contract._module_base
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous


@pytest.fixture
def manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    return instance


def patched_module_manager(manager: ModuleManager):
    """让插件管理器取到指定的模块管理器实例，构造与查询两条取法都覆盖。"""
    stub = Mock(return_value=manager)
    stub.get_existing_instance.return_value = manager
    return patch("app.runtime.extensions.plugin_manager.ModuleManager", stub)


def make_plugin(plugin_id: str, *, state: bool = True, provides=None, module_dict=None) -> Mock:
    """构造带 provides_modules / get_module 声明的插件替身。"""
    plugin = Mock()
    plugin.get_state.return_value = state
    plugin.get_name.return_value = plugin_id
    if provides is None:
        del plugin.provides_modules
    else:
        plugin.provides_modules = lambda: provides
    if module_dict is None:
        del plugin.get_module
    else:
        plugin.get_module = lambda: module_dict
    return plugin


# --------------------------------------------------------------------------- 契约校验


def test_contract_accepts_a_complete_module():
    """契约齐备的模块类应通过校验。"""
    passed, reasons = contract.verify_module_contract(StubModule)

    assert passed is True
    assert reasons == []


def test_contract_rejects_a_class_outside_the_module_base():
    """未继承模块基类的候选类应被拒绝。"""
    passed, reasons = contract.verify_module_contract(BrokenModule)

    assert passed is False
    assert any("未继承 _ModuleBase" in reason for reason in reasons)


def test_contract_rejects_lifecycle_methods_that_demand_extra_arguments():
    """生命周期方法索取额外必填参数时应被拒绝。"""
    passed, reasons = contract.verify_module_contract(DemandingModule)

    assert passed is False
    assert any("init_module 签名不兼容" in reason for reason in reasons)


def test_contract_rejects_a_class_with_unimplemented_abstract_methods():
    """抽象方法未落地的模块类应被拒绝。"""

    class AbstractStub(_ModuleBase):
        """只声明不实现的模块"""

    passed, reasons = contract.verify_module_contract(AbstractStub)

    assert passed is False
    assert any("抽象方法未实现" in reason for reason in reasons)


def test_contract_rejects_non_class_input():
    """非类对象不是合法的模块声明。"""
    passed, reasons = contract.verify_module_contract(StubModule())

    assert passed is False
    assert reasons == ["不是类对象"]


def test_contract_skips_the_base_class_check_when_not_configured():
    """基类未注入时降级跳过该项，其余契约照常校验。"""
    contract._module_base = None

    passed, _ = contract.verify_module_contract(BrokenModule)

    assert passed is True


# --------------------------------------------------------------------------- 注册面


def test_register_module_brings_the_module_into_dispatch(manager):
    """注册成功的模块应进入运行态并可被按方法名取到。"""
    assert manager.register_module(StubModule, owner="plugin_a") is True

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]
    assert manager.get_module("StubModule") is StubModule
    dispatched = list(manager.get_running_modules("stub_capability"))
    assert [module.stub_capability() for module in dispatched] == ["registered"]


def test_unregister_modules_stops_and_removes_by_owner(manager):
    """按来源卸载应停止运行实例并清空注册表，无残留。"""
    manager.register_module(StubModule, owner="plugin_a")
    manager.register_module(OtherStubModule, owner="plugin_b")
    running = manager.get_running_module("StubModule")

    removed = manager.unregister_modules("plugin_a")

    assert removed == ["StubModule"]
    assert running.stop_calls == 1
    assert manager.get_running_module("StubModule") is None
    assert manager.get_module("StubModule") is None
    assert manager.get_external_module_ids() == ["OtherStubModule"]


def test_register_module_is_idempotent_for_the_same_owner(manager):
    """同一来源重复注册不产生重复记账。"""
    assert manager.register_module(StubModule, owner="plugin_a") is True
    assert manager.register_module(StubModule, owner="plugin_a") is True

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]
    assert manager.unregister_modules("plugin_a") == ["StubModule"]


def test_register_module_rejects_a_name_taken_by_another_owner(manager):
    """模块标识被其它来源占用时拒绝注册，先到者胜。"""
    manager.register_module(StubModule, owner="plugin_a")

    assert manager.register_module(StubModule, owner="plugin_b") is False
    assert manager.get_external_module_ids("plugin_b") == []
    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]


def test_register_module_rejects_a_name_taken_by_a_builtin_module(manager):
    """内建模块的标识不可被插件遮蔽。"""
    manager._modules["StubModule"] = StubModule

    assert manager.register_module(StubModule, owner="plugin_a") is False
    assert manager.get_external_module_ids() == []


def test_register_module_rejects_a_contract_violation(manager):
    """未通过契约校验的类不得进入注册表。"""
    assert manager.register_module(BrokenModule, owner="plugin_a") is False

    assert manager.get_external_module_ids() == []
    assert manager.get_module("BrokenModule") is None


def test_register_module_rejects_an_empty_owner(manager):
    """缺少归属标识时无法记账，拒绝注册。"""
    assert manager.register_module(StubModule, owner="") is False


def test_register_module_keeps_a_switched_off_module_out_of_running_state(manager):
    """开关未打开的模块被接受但不上线。"""
    assert manager.register_module(DisabledStubModule, owner="plugin_a") is True

    assert manager.get_running_module("DisabledStubModule") is None
    assert manager.get_module("DisabledStubModule") is DisabledStubModule


def test_register_module_isolates_initialization_failures(manager):
    """模块初始化抛错不影响注册表其余条目。"""

    class ExplodingModule(StubModule):
        """初始化即抛错的模块"""

        def init_module(self) -> None:
            raise RuntimeError("boom")

    assert manager.register_module(ExplodingModule, owner="plugin_a") is True
    assert manager.register_module(StubModule, owner="plugin_a") is True

    assert manager.get_running_module("ExplodingModule") is None
    assert manager.get_running_module("StubModule") is not None


def test_reload_replays_external_modules(manager):
    """全量重扫后外部模块应按声明重新上线。"""
    manager.register_module(StubModule, owner="plugin_a")
    first = manager.get_running_module("StubModule")

    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]):
        manager.load_modules()

    replayed = manager.get_running_module("StubModule")
    assert replayed is not None
    assert replayed is not first
    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]


def test_register_module_is_safe_while_running_modules_are_iterated(manager):
    """运行期注册不得打断正在进行的运行态遍历。"""
    manager.register_module(StubModule, owner="plugin_a")

    iterator = manager.get_running_modules("stub_capability")
    next(iterator)
    manager.register_module(OtherStubModule, owner="plugin_b")

    assert list(iterator) == []
    assert len(list(manager.get_running_modules("stub_capability"))) == 2


def test_concurrent_registration_and_iteration_do_not_race(manager):
    """并发注册与遍历不得抛出字典变更异常。"""
    errors = []

    def register_many():
        for index in range(50):
            module = type(f"Concurrent{index}Module", (StubModule,), {})
            manager.register_module(module, owner=f"plugin_{index}")

    def iterate_many():
        try:
            for _ in range(200):
                list(manager.get_running_modules("stub_capability"))
                list(manager.get_running_type_modules(ModuleType.Other))
        except Exception as err:  # noqa: BLE001  并发缺陷会以任意异常形式暴露
            errors.append(err)

    threads = [threading.Thread(target=register_many), threading.Thread(target=iterate_many)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []


# --------------------------------------------------------------------------- ProvidedModule


def test_provided_module_defaults_to_the_class_name(manager):
    """裸类与等价的 ProvidedModule 声明行为一致。"""
    assert manager.register_module(ProvidedModule(StubModule), owner="plugin_a") is True

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]
    assert manager.get_running_module("StubModule") is not None


def test_provided_module_honours_a_custom_id_and_factory(manager):
    """声明可自定义模块标识与实例构造方式。"""
    built = StubModule()
    declaration = ProvidedModule(StubModule, module_id="custom_stub", factory=lambda: built)

    assert manager.register_module(declaration, owner="plugin_a") is True

    assert manager.get_external_module_ids("plugin_a") == ["custom_stub"]
    assert manager.get_running_module("custom_stub") is built
    assert manager.unregister_modules("plugin_a") == ["custom_stub"]
    assert built.stop_calls == 1


def test_provided_module_still_validates_the_module_class(manager):
    """契约仍针对模块类校验，工厂不能绕过。"""
    declaration = ProvidedModule(BrokenModule, factory=BrokenModule)

    assert manager.register_module(declaration, owner="plugin_a") is False


# --------------------------------------------------------------------------- 聚合器


def test_aggregator_collects_declarations_per_plugin():
    """按插件归集非空声明。"""
    plugins = {"plugin_a": make_plugin("plugin_a", provides=[StubModule])}

    assert get_plugin_provided_modules(plugins) == {"plugin_a": [StubModule]}


def test_aggregator_skips_disabled_plugins():
    """未启用的插件不参与声明聚合。"""
    plugins = {"plugin_a": make_plugin("plugin_a", state=False, provides=[StubModule])}

    assert get_plugin_provided_modules(plugins) == {}


def test_aggregator_omits_plugins_without_declarations():
    """空声明不产生条目。"""
    plugins = {
        "plugin_a": make_plugin("plugin_a", provides=[]),
        "plugin_b": make_plugin("plugin_b"),
    }

    assert get_plugin_provided_modules(plugins) == {}


def test_aggregator_isolates_a_failing_hook():
    """单个插件钩子抛错不影响其余插件。"""

    def explode():
        raise RuntimeError("boom")

    broken = make_plugin("plugin_a", provides=[])
    broken.provides_modules = explode
    plugins = {"plugin_a": broken, "plugin_b": make_plugin("plugin_b", provides=[StubModule])}

    assert get_plugin_provided_modules(plugins) == {"plugin_b": [StubModule]}


def test_aggregator_filters_by_plugin_id():
    """指定插件时只聚合该插件的声明。"""
    plugins = {
        "plugin_a": make_plugin("plugin_a", provides=[StubModule]),
        "plugin_b": make_plugin("plugin_b", provides=[OtherStubModule]),
    }

    assert get_plugin_provided_modules(plugins, pid="plugin_b") == {"plugin_b": [OtherStubModule]}


# --------------------------------------------------------------------------- 废弃告警


def test_injection_declaration_warns_once_per_plugin():
    """注入式声明按插件去重告警，不随分发次数增长。"""
    policy.reset_warned()
    plugins = {
        "plugin_a": make_plugin("plugin_a", module_dict={"stub_capability": lambda: "injected"}),
    }

    with patch("app.runtime.extensions.plugin_spi.logger") as spi_logger:
        for _ in range(5):
            get_plugin_modules(plugins)

    assert spi_logger.warning.call_count == 0
    policy.reset_warned()


def test_injection_declaration_emits_the_registered_deprecation_notice():
    """注入式声明命中已登记的废弃提示。"""
    policy.reset_warned()
    plugins = {
        "plugin_a": make_plugin("plugin_a", module_dict={"stub_capability": lambda: "injected"}),
    }

    with patch("app.runtime.deprecation.policy.logger") as policy_logger:
        for _ in range(5):
            get_plugin_modules(plugins)

    assert policy_logger.warning.call_count == 1
    assert "get_module()" in policy_logger.warning.call_args[0][0]
    assert "plugin_a" in policy_logger.warning.call_args[0][0]
    policy.reset_warned()


def test_mixed_declaration_warns_once_in_addition_to_the_injection_notice():
    """两种声明并存时额外给出一次性提示。"""
    policy.reset_warned()
    plugins = {
        "plugin_a": make_plugin(
            "plugin_a",
            provides=[StubModule],
            module_dict={"stub_capability": lambda: "injected"},
        ),
    }

    with patch("app.runtime.deprecation.policy.logger") as policy_logger:
        for _ in range(3):
            get_plugin_provided_modules(plugins)

    assert policy_logger.warning.call_count == 1
    assert "并存" in policy_logger.warning.call_args[0][0]
    policy.reset_warned()


def test_registered_only_plugin_triggers_no_deprecation_notice():
    """只用注册式的插件不应收到废弃提示。"""
    policy.reset_warned()
    plugins = {"plugin_a": make_plugin("plugin_a", provides=[StubModule])}

    with patch("app.runtime.deprecation.policy.logger") as policy_logger:
        get_plugin_provided_modules(plugins)

    assert policy_logger.warning.call_count == 0
    policy.reset_warned()


# --------------------------------------------------------------------------- 生命周期编排


def test_plugin_manager_registers_and_unregisters_declared_modules(manager):
    """插件启停应带动其声明模块的上线与回收。"""
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {"plugin_a": object}
    plugin_manager._running_plugins = {"plugin_a": make_plugin("plugin_a", provides=[StubModule])}

    with patched_module_manager(manager):
        plugin_manager._register_plugin_modules("plugin_a")
        assert manager.get_external_module_ids("plugin_a") == ["StubModule"]

        plugin_manager._unregister_plugin_modules("plugin_a")

    assert manager.get_external_module_ids() == []


def test_plugin_manager_registration_is_idempotent_across_reinitialization(manager):
    """反复初始化插件不得累积重复模块。"""
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {"plugin_a": object}
    plugin_manager._running_plugins = {"plugin_a": make_plugin("plugin_a", provides=[StubModule])}

    with patched_module_manager(manager):
        for _ in range(3):
            plugin_manager._unregister_plugin_modules("plugin_a")
            plugin_manager._register_plugin_modules("plugin_a")

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]


def test_plugin_manager_unregisters_a_plugin_that_never_ran(manager):
    """插件未进入运行态时仍按来源回收其模块。"""
    manager.register_module(StubModule, owner="plugin_a")
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {"plugin_a": object}
    plugin_manager._running_plugins = {}

    with patched_module_manager(manager):
        plugin_manager._unregister_plugin_modules()

    assert manager.get_external_module_ids() == []


def test_registration_does_not_instantiate_the_module_manager_without_declarations():
    """没有插件声明模块时不触发模块管理器装载。"""
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._running_plugins = {"plugin_a": make_plugin("plugin_a")}

    with patch("app.runtime.extensions.plugin_manager.ModuleManager") as module_manager:
        plugin_manager._register_plugin_modules()

    module_manager.assert_not_called()


# --------------------------------------------------------------------------- 两种方式并存


def test_injected_and_registered_declarations_both_take_effect(manager):
    """同一插件的注入式与注册式声明互不去重，均保留。"""
    plugin = make_plugin(
        "plugin_a",
        provides=[StubModule],
        module_dict={"stub_capability": lambda: "injected"},
    )
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {"plugin_a": object}
    plugin_manager._running_plugins = {"plugin_a": plugin}

    with patched_module_manager(manager):
        plugin_manager._register_plugin_modules("plugin_a")

    injected = get_plugin_modules(plugin_manager.running_plugins)
    assert injected[("plugin_a", "plugin_a")]["stub_capability"]() == "injected"
    registered = list(manager.get_running_modules("stub_capability"))
    assert [module.stub_capability() for module in registered] == ["registered"]
