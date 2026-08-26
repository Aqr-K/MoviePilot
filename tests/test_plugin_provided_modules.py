"""插件声明模块方法表链路测试：契约校验、与 get_module() 并存、分发接入。"""

from types import SimpleNamespace
from typing import Iterator

import pytest

from app.runtime.deprecation import policy as deprecation_policy
from app.runtime.extensions.contract.declaration import (
    ModuleDeclaration,
    declaration_module_priority,
)
from app.runtime.extensions.projection.dispatcher import ModuleInvocationDispatcher
from app.runtime.extensions.admission import module
from app.runtime.extensions.projection import plugin as projection_module
from app.runtime.extensions.projection.plugin import PluginProjection, PluginProviderSource


@pytest.fixture(autouse=True)
def _clean_deprecation_warned() -> Iterator[None]:
    """每个用例前后都清空废弃告警去重记录，避免用例间互相掩盖。"""
    deprecation_policy.reset_warned()
    yield
    deprecation_policy.reset_warned()


@pytest.fixture(autouse=True)
def _clean_overlap_warnings() -> Iterator[None]:
    """每个用例前后都清空模块来源重叠告警去重记录，避免用例间互相掩盖。"""
    projection_module._module_source_overlap_warnings_seen.clear()
    yield
    projection_module._module_source_overlap_warnings_seen.clear()


class _Plugin(SimpleNamespace):
    """提供可配置插件 hook 的最小运行态插件替身。"""

    def __init__(self, enabled=True, **hooks):
        """保存启用状态、插件名称和 hook 实现。"""
        super().__init__(plugin_name=hooks.pop("plugin_name", "测试插件"), **hooks)
        self._enabled = enabled

    def get_state(self):
        """返回预设启用状态。"""
        return self._enabled

    def get_name(self):
        """返回插件展示名称。"""
        return self.plugin_name


class _CapableModulePlugin:
    """声明模块方法表的最小插件桩，用于直接驱动 PluginProjection。"""

    plugin_name = "模块插件"

    def __init__(self, enabled=True, declarations=None, raise_error=False):
        self._enabled = enabled
        self._declarations = declarations
        self._raise_error = raise_error

    def get_state(self) -> bool:
        """返回插件启用状态。"""
        return self._enabled

    def get_name(self) -> str:
        """返回插件展示名称。"""
        return self.plugin_name

    def provides_modules(self):
        """返回声明的模块方法表，或按需抛出异常模拟插件实现出错。"""
        if self._raise_error:
            raise RuntimeError("声明模块方法表时出错")
        return self._declarations


def _handler() -> str:
    """契约校验用的最小可调用桩。"""
    return "ok"


# ---------------------------------------------------------------------------
# 契约校验
# ---------------------------------------------------------------------------


def test_contract_accepts_valid_declaration() -> None:
    """方法表非空、键值均合法时声明合规。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler})

    assert module.module_declaration_violation(declaration) is None


def test_contract_accepts_bare_dict_declaration() -> None:
    """插件直接交出方法表字典而不包 ModuleDeclaration 时同样合规。"""
    assert module.module_declaration_violation({"recognize": _handler}) is None


@pytest.mark.parametrize(
    "declaration",
    [
        ModuleDeclaration(methods={}),
        ModuleDeclaration(),
    ],
    ids=["empty_methods", "methods_unset"],
)
def test_contract_rejects_empty_methods(declaration) -> None:
    """方法表为空映射的声明必须被拒绝。"""
    violation = module.module_declaration_violation(declaration)

    assert violation is not None


def test_contract_rejects_non_string_method_name() -> None:
    """方法名不是字符串的声明必须被拒绝。"""
    declaration = ModuleDeclaration(methods={1: _handler})

    violation = module.module_declaration_violation(declaration)

    assert violation is not None


def test_contract_rejects_blank_method_name() -> None:
    """方法名为空白字符串的声明必须被拒绝。"""
    declaration = ModuleDeclaration(methods={"   ": _handler})

    violation = module.module_declaration_violation(declaration)

    assert violation is not None


def test_contract_rejects_non_callable_method_value() -> None:
    """方法名对应值不可调用的声明必须被拒绝。"""
    declaration = ModuleDeclaration(methods={"recognize": "not-callable"})

    violation = module.module_declaration_violation(declaration)

    assert violation is not None


# ---------------------------------------------------------------------------
# priority 字段
# ---------------------------------------------------------------------------


def test_priority_defaults_to_zero() -> None:
    """未显式声明 priority 时默认为 0，与内建模块最常见的中性取值一致。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler})

    assert declaration.priority == 0


def test_priority_explicit_value_is_preserved() -> None:
    """显式声明的 priority 原样保留，不被归一或改写。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler}, priority=7)

    assert declaration.priority == 7


def test_declaration_module_priority_reads_module_declaration() -> None:
    """`declaration_module_priority` 从 ModuleDeclaration 实例读出 priority 原始值。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler}, priority=3)

    assert declaration_module_priority(declaration) == 3


def test_declaration_module_priority_missing_on_bare_dict_is_none() -> None:
    """插件直接交出方法表字典时没有 priority 字段，读取结果为 None 而非 0。"""
    assert declaration_module_priority({"recognize": _handler}) is None


def test_contract_accepts_explicit_integer_priority() -> None:
    """priority 为整数时声明合规。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler}, priority=5)

    assert module.module_declaration_violation(declaration) is None


def test_contract_accepts_bare_dict_without_priority_field() -> None:
    """兼容旧写法：方法表字典没有 priority 字段时仍视为合规，缺省即不参与排序。"""
    assert module.module_declaration_violation({"recognize": _handler}) is None


def test_contract_rejects_non_integer_priority() -> None:
    """priority 给出但不是整数时声明必须被拒绝。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler}, priority="high")

    violation = module.module_declaration_violation(declaration)

    assert violation is not None


def test_contract_rejects_boolean_priority() -> None:
    """priority 给出 bool 时必须被拒绝：bool 是 int 子类，不能被当成合法排序位。"""
    declaration = ModuleDeclaration(methods={"recognize": _handler}, priority=True)

    violation = module.module_declaration_violation(declaration)

    assert violation is not None


# ---------------------------------------------------------------------------
# PluginProjection.provided_modules() / modules() 投影
# ---------------------------------------------------------------------------


def test_projection_accepts_valid_declaration() -> None:
    """契约合规的声明应被接受，字段原样保留。"""
    plugin = _CapableModulePlugin(
        declarations=[
            ModuleDeclaration(methods={"recognize": _handler})
        ]
    )
    projection = PluginProjection({"DemoModule": plugin})

    declared = projection.provided_modules()

    assert len(declared["DemoModule"]) == 1
    accepted = declared["DemoModule"][0]
    assert accepted.methods == {"recognize": _handler}


def test_projection_preserves_priority_field() -> None:
    """provided_modules() 投影产出的是原始声明对象，priority 字段随之原样保留。

    modules() 之后的合并步骤把多条声明拍平成一张 {方法名: 实现} 表，priority 只在
    provided_modules() 这一层的声明对象上还看得到；这正是当前投影层「正确携带」
    该字段的方式，而不是在拍平后的方法表里发明一个新位置存放它。
    """
    plugin = _CapableModulePlugin(
        declarations=[
            ModuleDeclaration(methods={"recognize": _handler}, priority=9)
        ]
    )
    projection = PluginProjection({"DemoModule": plugin})

    declared = projection.provided_modules()

    assert declared["DemoModule"][0].priority == 9


def test_projection_accepts_bare_dict_without_wrapper() -> None:
    """插件直接交出方法表字典而不包 ModuleDeclaration 的兼容写法应被接受。"""
    plugin = _CapableModulePlugin(declarations=[{"recognize": _handler}])
    projection = PluginProjection({"DemoModule": plugin})

    declared = projection.provided_modules()

    assert declared["DemoModule"] == [{"recognize": _handler}]


def test_projection_partial_rejection_keeps_valid_siblings() -> None:
    """同一实例声明多条时，不合契约的条目被跳过，合规的条目照常保留。"""
    plugin = _CapableModulePlugin(
        declarations=[
            ModuleDeclaration(methods={"ok": _handler}),
            ModuleDeclaration(methods={}),
            ModuleDeclaration(methods={"bad": "not-callable"}),
        ]
    )
    projection = PluginProjection({"DemoModule": plugin})

    declared = projection.provided_modules()

    assert len(declared["DemoModule"]) == 1
    assert declared["DemoModule"][0].methods == {"ok": _handler}


def test_projection_swallows_plugin_exception_without_blocking_others() -> None:
    """单个插件声明模块方法表抛异常时不应影响其它插件的投影结果。"""
    broken = _CapableModulePlugin(raise_error=True)
    healthy = _CapableModulePlugin(declarations=[ModuleDeclaration(methods={"ok": _handler})])
    projection = PluginProjection({"Broken": broken, "Ok": healthy})

    declared = projection.provided_modules()

    assert "Broken" not in declared
    assert declared["Ok"][0].methods == {"ok": _handler}


def test_modules_includes_declared_methods() -> None:
    """声明式方法表须并入 modules() 产出的分发方法表。"""
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": _handler})]
    )
    projection = PluginProjection({"DemoModule": plugin})

    modules = projection.modules()

    assert modules == {("DemoModule", "模块插件"): {"recognize": _handler}}


def test_modules_merges_declared_and_legacy_sources() -> None:
    """同一实例的声明式方法表与 get_module() 方法表须合并到同一张分发表。"""

    def _legacy() -> str:
        return "legacy"

    plugin = _Plugin(
        provides_modules=lambda: [ModuleDeclaration(methods={"recognize": _handler})],
        get_module=lambda: {"match": _legacy},
    )
    projection = PluginProjection({"Demo": plugin})

    modules = projection.modules()

    assert modules == {("Demo", "测试插件"): {"recognize": _handler, "match": _legacy}}


def test_modules_declared_source_wins_on_name_overlap() -> None:
    """同一实例的两条来源挂载同一方法名时，声明式登记优先生效。"""

    def _legacy_recognize() -> str:
        return "legacy"

    plugin = _Plugin(
        provides_modules=lambda: [ModuleDeclaration(methods={"recognize": _handler})],
        get_module=lambda: {"recognize": _legacy_recognize},
    )
    projection = PluginProjection({"Demo": plugin})

    modules = projection.modules()

    assert modules[("Demo", "测试插件")]["recognize"] is _handler


def test_modules_overlap_warning_fires_once() -> None:
    """两条来源挂载同一方法名时须告警一次，重复投影不重复告警。"""
    errors = []
    log = SimpleNamespace(
        error=lambda message: errors.append(message),
        warning=lambda message: errors.append(message),
    )
    plugin = _Plugin(
        provides_modules=lambda: [ModuleDeclaration(methods={"recognize": _handler})],
        get_module=lambda: {"recognize": lambda: "legacy"},
    )
    projection = PluginProjection({"Demo": plugin}, log=log)

    projection.modules()
    projection.modules()

    overlap_messages = [m for m in errors if "同时挂载方法名" in m]
    assert len(overlap_messages) == 1


def test_modules_legacy_deprecation_warning_still_fires(monkeypatch) -> None:
    """get_module() 一侧的废弃告警不因新增声明式钩子而失效。"""
    emitted = []
    monkeypatch.setattr(deprecation_policy.logger, "warning", emitted.append)
    plugin = _Plugin(get_module=lambda: {"recognize": _handler})
    projection = PluginProjection({"Demo": plugin})

    projection.modules()

    assert len(emitted) == 1
    assert "get_module" in emitted[0]


def test_modules_sibling_instance_exception_does_not_block_healthy_instance() -> None:
    """一个实例的模块声明抛异常时，兄弟实例的分发方法表不受影响。"""
    broken = _CapableModulePlugin(raise_error=True)
    healthy = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"ok": _handler})]
    )
    healthy.plugin_name = "健康插件"
    projection = PluginProjection({"Broken": broken, "Healthy": healthy})

    modules = projection.modules()

    assert ("Healthy", "健康插件") in modules
    assert modules[("Healthy", "健康插件")] == {"ok": _handler}
    assert not any(key[0] == "Broken" for key in modules)


# ---------------------------------------------------------------------------
# 三级分发接入
# ---------------------------------------------------------------------------


class _PluginCatalog:
    """把 PluginProjection.modules() 的产出适配为调度器消费的目录端口。"""

    def __init__(self, projection: PluginProjection) -> None:
        """保存被适配的插件能力投影。"""
        self._projection = projection

    def get_plugin_modules(self) -> dict:
        """返回当前插件模块方法表快照。"""
        return self._projection.modules()


def _dispatcher(projection: PluginProjection) -> ModuleInvocationDispatcher:
    """构造只接插件来源、不接宿主模块的最小调度器，用于验证声明式方法表可分发。"""

    class _EmptyModuleCatalog:
        """不提供任何宿主模块的空目录。"""

        def get_running_modules(self, _method: str):
            """始终返回空序列。"""
            return []

        def providers_for(self, _method: str):
            """始终返回空序列。"""
            return ()

    return ModuleInvocationDispatcher(
        module_catalog=_EmptyModuleCatalog(),
        plugin_catalog=_PluginCatalog(projection),
        plugin_error_handler=lambda *a, **k: None,
        system_error_handler=lambda *a, **k: None,
        rate_limit_handler=lambda *a, **k: None,
    )


def test_declared_module_method_participates_in_unicast_dispatch() -> None:
    """provides_modules() 声明的方法须能被单播分发触达并取得返回值。"""
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": lambda: "declared"})]
    )
    projection = PluginProjection({"DemoModule": plugin})
    dispatcher = _dispatcher(projection)

    assert dispatcher.unicast("recognize") == "declared"


def test_declared_module_method_participates_in_multicast_dispatch() -> None:
    """provides_modules() 声明的方法须能被多播分发收集到结果列表中。"""
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": lambda: "declared"})]
    )
    projection = PluginProjection({"DemoModule": plugin})
    dispatcher = _dispatcher(projection)

    assert dispatcher.multicast("recognize") == ["declared"]


def test_declared_module_method_participates_in_broadcast_dispatch() -> None:
    """provides_modules() 声明的方法须能被广播分发触达。"""
    calls = []
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"notify": lambda: calls.append(1)})]
    )
    projection = PluginProjection({"DemoModule": plugin})
    dispatcher = _dispatcher(projection)

    dispatcher.broadcast("notify")

    assert calls == [1]


def test_contract_invalid_declaration_never_reaches_dispatch() -> None:
    """契约不合规的声明被投影层拒绝，不会作为分发方法表的一部分被调用方触达。"""
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": "not-callable"})]
    )
    projection = PluginProjection({"DemoModule": plugin})
    dispatcher = _dispatcher(projection)

    assert dispatcher.unicast("recognize") is None


def test_provider_source_yields_declared_provider_for_matching_method() -> None:
    """PluginProviderSource 须按方法名精确产出声明式方法表登记的提供者。"""
    plugin = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": _handler})]
    )
    projection = PluginProjection({"DemoModule": plugin})
    source = PluginProviderSource(_PluginCatalog(projection))

    providers = list(source.notify_providers("recognize"))

    assert len(providers) == 1
    assert providers[0].extension_id == "DemoModule"
    assert providers[0].invoke() == "ok"


def test_plugin_priority_does_not_yet_govern_dispatch_order() -> None:
    """记录当前事实：插件声明的 priority 尚未接入分发排序。

    `PluginProviderSource._providers()` 按目录字典的登记顺序产出提供者，不读取
    `ModuleDeclaration.priority`；与之相对，宿主内建模块目录
    （`app.runtime.extensions.module_manager.ModuleManager.providers_for`）确实按
    `get_priority()` 升序排列。本用例把「数值更小、优先级更高」的声明放在后登记的
    插件上，验证 unicast 仍然应答先登记的插件而不是优先级更高的插件——排序逻辑
    需在模块外挂阶段一并设计，当前不能假定它已经生效。
    """
    later_but_higher_priority = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": lambda: "second"}, priority=0)]
    )
    later_but_higher_priority.plugin_name = "后登记但优先级更高"
    earlier_but_lower_priority = _CapableModulePlugin(
        declarations=[ModuleDeclaration(methods={"recognize": lambda: "first"}, priority=99)]
    )
    earlier_but_lower_priority.plugin_name = "先登记但优先级更低"
    projection = PluginProjection({
        "Earlier": earlier_but_lower_priority,
        "Later": later_but_higher_priority,
    })
    dispatcher = _dispatcher(projection)

    assert dispatcher.unicast("recognize") == "first"
