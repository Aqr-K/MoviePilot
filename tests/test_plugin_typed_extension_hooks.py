"""插件按类型细分的模块声明钩子与智能体工具声明钩子。"""
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import pytest

from app.modules import _ModuleBase
from app.runtime.deprecation import policy
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager, ProvidedModule
from app.runtime.extensions.plugin_spi import (
    clear_plugin_agent_tools_cache,
    get_plugin_agent_tools,
    get_plugin_provided_modules,
)
from app.schemas.types import ModuleType


class TypedStubModule(_ModuleBase):
    """满足模块契约、类型可在类上取到的最小实现"""

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
        return "TypedStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Downloader

    @staticmethod
    def get_subtype():
        return None

    @staticmethod
    def get_priority() -> int:
        return 0


class MediaServerStubModule(TypedStubModule):
    """类型为媒体服务器的模块"""

    @staticmethod
    def get_name() -> str:
        return "MediaServerStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaServer


class NotificationStubModule(TypedStubModule):
    """类型为消息服务的模块"""

    @staticmethod
    def get_name() -> str:
        return "NotificationStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Notification


class DataSourceStubModule(TypedStubModule):
    """类型为媒体识别的模块"""

    @staticmethod
    def get_name() -> str:
        return "DataSourceStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaRecognize


class StorageStubModule(TypedStubModule):
    """类型为存储的模块"""

    @staticmethod
    def get_name() -> str:
        return "StorageStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Storage

    @staticmethod
    def get_subtype():
        return "stub_storage"


class OtherTypeStubModule(TypedStubModule):
    """类型为其它的模块"""

    @staticmethod
    def get_name() -> str:
        return "OtherTypeStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Other


class InstanceTypedModule(TypedStubModule):
    """把类型判定写成实例方法的模块"""

    @staticmethod
    def get_name() -> str:
        return "InstanceTypedStub"

    def get_type(self) -> ModuleType:
        """取模块类型，只能在实例上判定"""
        return ModuleType.MediaServer


class StubToolBase:
    """智能体工具基类替身"""


class GoodTool(StubToolBase):
    """满足工具契约的最小实现"""

    name = "good_tool"
    description = "做点什么"

    async def run(self) -> str:
        """执行工具"""
        return "ok"


class NoDescriptionTool(StubToolBase):
    """缺少说明的工具"""

    name = "no_description_tool"
    description = ""

    async def run(self) -> str:
        """执行工具"""
        return "ok"


class SyncRunTool(StubToolBase):
    """把执行入口写成同步方法的工具"""

    name = "sync_run_tool"
    description = "做点什么"

    def run(self) -> str:
        """执行工具"""
        return "ok"


class ForeignTool:
    """未继承工具基类的候选类"""

    name = "foreign_tool"
    description = "做点什么"

    async def run(self) -> str:
        """执行工具"""
        return "ok"


@pytest.fixture(autouse=True)
def contract_bases_configured():
    """按启动组合根的方式装配模块与工具基类，用例结束后还原。"""
    previous_module_base = contract._module_base
    previous_tool_base = contract._agent_tool_base
    contract.configure_module_base(_ModuleBase)
    contract.configure_agent_tool_base(StubToolBase)
    yield
    contract._module_base = previous_module_base
    contract._agent_tool_base = previous_tool_base


@pytest.fixture(autouse=True)
def clean_agent_tools_cache():
    """隔离智能体工具注册表缓存，避免用例之间互相看到对方的快照。"""
    clear_plugin_agent_tools_cache()
    yield
    clear_plugin_agent_tools_cache()


@pytest.fixture(autouse=True)
def clean_deprecation_state():
    """清空废弃告警去重状态，使每个用例都能观察到首次告警。"""
    policy.reset_warned()
    yield
    policy.reset_warned()


@pytest.fixture
def manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    return instance


# 插件替身需要显式暴露或摘除的全部声明钩子
PLUGIN_HOOKS = (
    "provides_modules",
    "provides_downloaders",
    "provides_mediaservers",
    "provides_notifications",
    "provides_data_sources",
    "provides_storages",
    "provides_channel_capabilities",
    "provides_agent_tools",
    "get_agent_tools",
    "get_module",
)


def make_plugin(plugin_id: str, *, state: bool = True, **hooks) -> Mock:
    """
    构造只暴露指定声明钩子的插件替身

    :param plugin_id: 插件标识
    :param state: 插件启用状态
    :param hooks: 钩子名到返回值的映射，未列出的钩子在替身上不存在
    :return: 插件替身
    """
    plugin = Mock()
    plugin.get_state.return_value = state
    plugin.get_name.return_value = plugin_id
    plugin.plugin_name = plugin_id
    for hook_name in PLUGIN_HOOKS:
        if hook_name in hooks:
            setattr(plugin, hook_name, lambda _value=hooks[hook_name]: _value)
        else:
            delattr(plugin, hook_name)
    return plugin


# --------------------------------------------------------------------------- 类型细分声明


def test_typed_hook_declares_a_module_with_its_expected_type():
    """下载器钩子的声明带上下载器类型，交给模块管理器判定。"""
    plugins = {"Demo": make_plugin("Demo", provides_downloaders=[TypedStubModule])}

    provided = get_plugin_provided_modules(plugins)

    declaration = provided["Demo"][0]
    assert isinstance(declaration, ProvidedModule)
    assert declaration.module_cls is TypedStubModule
    assert declaration.expected_type is ModuleType.Downloader


def test_typed_hook_rejects_a_module_of_another_type(manager):
    """类型不符的模块经细分钩子声明时被拒绝注册。"""
    declaration = ProvidedModule(OtherTypeStubModule, expected_type=ModuleType.Downloader)

    accepted = manager.register_module(declaration, owner="Demo")

    assert accepted is False
    assert manager.get_running_module("OtherTypeStubModule") is None


def test_generic_hook_still_accepts_the_same_module(manager):
    """同一个模块经通用钩子声明时不做类型判定，仍被接受。"""
    accepted = manager.register_module(OtherTypeStubModule, owner="Demo")

    assert accepted is True
    assert manager.get_running_module("OtherTypeStubModule") is not None


@pytest.mark.parametrize("hook_name, module_cls, expected_type", [
    ("provides_downloaders", TypedStubModule, ModuleType.Downloader),
    ("provides_mediaservers", MediaServerStubModule, ModuleType.MediaServer),
    ("provides_notifications", NotificationStubModule, ModuleType.Notification),
    ("provides_data_sources", DataSourceStubModule, ModuleType.MediaRecognize),
    ("provides_storages", StorageStubModule, ModuleType.Storage),
])
def test_each_typed_hook_carries_its_own_module_type(hook_name, module_cls, expected_type):
    """每个细分钩子给声明附上各自的模块类型。"""
    plugins = {"Demo": make_plugin("Demo", **{hook_name: [module_cls]})}

    declaration = get_plugin_provided_modules(plugins)["Demo"][0]

    assert declaration.module_cls is module_cls
    assert declaration.expected_type is expected_type


@pytest.mark.parametrize("module_cls, expected_type", [
    (MediaServerStubModule, ModuleType.Downloader),
    (TypedStubModule, ModuleType.MediaServer),
    (TypedStubModule, ModuleType.Notification),
    (TypedStubModule, ModuleType.MediaRecognize),
    (TypedStubModule, ModuleType.Storage),
])
def test_every_module_type_mismatch_is_rejected(manager, module_cls, expected_type):
    """任一细分类型与模块实际类型不符时都被拒绝。"""
    declaration = ProvidedModule(module_cls, expected_type=expected_type)

    assert manager.register_module(declaration, owner="Demo") is False


def test_module_type_written_as_an_instance_method_is_not_judged(manager):
    """类型判定写成实例方法时无法在注册前取值，只校验基础契约。"""
    declaration = ProvidedModule(InstanceTypedModule, expected_type=ModuleType.Downloader)

    assert manager.register_module(declaration, owner="Demo") is True


def test_a_declaration_keeps_its_own_expected_type():
    """声明自带期望类型时细分钩子不覆盖它。"""
    own = ProvidedModule(MediaServerStubModule, expected_type=ModuleType.MediaServer)
    plugins = {"Demo": make_plugin("Demo", provides_mediaservers=[own])}

    declaration = get_plugin_provided_modules(plugins)["Demo"][0]

    assert declaration is own


def test_generic_and_typed_declarations_coexist():
    """同一插件的通用声明与细分声明合并在同一条来源下。"""
    plugins = {"Demo": make_plugin("Demo",
                                   provides_modules=[OtherTypeStubModule],
                                   provides_downloaders=[TypedStubModule])}

    declared = get_plugin_provided_modules(plugins)["Demo"]

    assert [getattr(item, "module_cls", item) for item in declared] == [
        OtherTypeStubModule, TypedStubModule
    ]


def test_disabled_instance_declares_nothing():
    """未启用的实例不参与声明聚合。"""
    plugins = {"Demo": make_plugin("Demo", state=False, provides_downloaders=[TypedStubModule])}

    assert get_plugin_provided_modules(plugins) == {}


def test_one_broken_hook_does_not_stop_other_plugins():
    """单个实例的钩子异常不影响其余实例的聚合结果。"""
    broken = make_plugin("Broken", provides_downloaders=[])
    broken.provides_downloaders = Mock(side_effect=RuntimeError("boom"))
    plugins = {
        "Broken": broken,
        "Demo": make_plugin("Demo", provides_downloaders=[TypedStubModule]),
    }

    provided = get_plugin_provided_modules(plugins)

    assert "Broken" not in provided
    assert provided["Demo"][0].module_cls is TypedStubModule


def test_an_uninspectable_hook_only_skips_its_own_instance():
    """钩子无法内省时只跳过该实例，其余实例照常聚合。"""
    opaque = make_plugin("Opaque", provides_downloaders=[])
    opaque.provides_downloaders = object()
    plugins = {
        "Opaque": opaque,
        "Demo": make_plugin("Demo", provides_downloaders=[TypedStubModule]),
    }

    provided = get_plugin_provided_modules(plugins)

    assert "Opaque" not in provided
    assert provided["Demo"][0].module_cls is TypedStubModule


# --------------------------------------------------------------------------- 智能体工具声明


def test_declared_agent_tool_is_collected():
    """满足契约的工具经声明钩子交出后进入工具注册表。"""
    plugins = {"Demo": make_plugin("Demo", provides_agent_tools=[GoodTool])}

    collected = get_plugin_agent_tools(plugins)

    assert collected == [{"plugin_id": "Demo", "plugin_name": "Demo", "tools": [GoodTool]}]


@pytest.mark.parametrize("tool_cls", [NoDescriptionTool, SyncRunTool, ForeignTool, "not_a_class"])
def test_declared_agent_tool_failing_the_contract_is_rejected(tool_cls):
    """不满足契约的工具在声明阶段就被拒绝。"""
    plugins = {"Demo": make_plugin("Demo", provides_agent_tools=[tool_cls])}

    assert get_plugin_agent_tools(plugins) == []


@pytest.mark.parametrize("tool_cls", [NoDescriptionTool, SyncRunTool, ForeignTool])
def test_legacy_hook_still_hands_over_the_same_broken_tool(tool_cls):
    """同一个不合契约的工具经旧钩子交出时不做校验，仍被收下。"""
    plugins = {"Demo": make_plugin("Demo", get_agent_tools=[tool_cls])}

    collected = get_plugin_agent_tools(plugins)

    assert collected[0]["tools"] == [tool_cls]


def test_legacy_agent_tools_hook_warns_once():
    """旧钩子交出工具时发出废弃提示，同一来源只留一次痕迹。"""
    plugins = {"Demo": make_plugin("Demo", get_agent_tools=[GoodTool])}

    with patch("app.runtime.deprecation.policy.logger") as policy_logger:
        get_plugin_agent_tools(plugins)
        clear_plugin_agent_tools_cache()
        get_plugin_agent_tools(plugins)

    assert policy_logger.warning.call_count == 1
    assert "get_agent_tools()" in policy_logger.warning.call_args[0][0]
    assert "Demo" in policy_logger.warning.call_args[0][0]


def test_declared_agent_tools_trigger_no_deprecation_notice():
    """只用声明式钩子的插件不触发任何废弃提示。"""
    plugins = {"Demo": make_plugin("Demo", provides_agent_tools=[GoodTool])}

    with patch("app.runtime.deprecation.policy.logger") as policy_logger:
        get_plugin_agent_tools(plugins)

    assert policy_logger.warning.call_count == 0


def test_declared_and_legacy_tools_merge_under_one_source():
    """两种声明方式并存时工具合并在同一条来源下，声明式在前。"""
    plugins = {"Demo": make_plugin("Demo",
                                   provides_agent_tools=[GoodTool],
                                   get_agent_tools=[ForeignTool])}

    collected = get_plugin_agent_tools(plugins)

    assert collected[0]["tools"] == [GoodTool, ForeignTool]


def test_disabled_instance_declares_no_agent_tools():
    """未启用的实例不交出任何工具。"""
    plugins = {"Demo": make_plugin("Demo", state=False, provides_agent_tools=[GoodTool])}

    assert get_plugin_agent_tools(plugins) == []


def test_agent_tools_are_filtered_by_plugin_id():
    """按插件筛选时只取该插件的工具。"""
    plugins = {
        "Demo": make_plugin("Demo", provides_agent_tools=[GoodTool]),
        "Other": make_plugin("Other", provides_agent_tools=[GoodTool]),
    }

    collected = get_plugin_agent_tools(plugins, "Demo")

    assert [item["plugin_id"] for item in collected] == ["Demo"]


def test_tool_contract_skips_inheritance_when_no_base_is_configured():
    """工具基类未装配时跳过继承判定，其余条目照常校验。"""
    contract._agent_tool_base = None
    plugins = {"Demo": make_plugin("Demo", provides_agent_tools=[ForeignTool, SyncRunTool])}

    collected = get_plugin_agent_tools(plugins)

    assert collected[0]["tools"] == [ForeignTool]
