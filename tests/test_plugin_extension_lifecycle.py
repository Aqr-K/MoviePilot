"""插件扩展点的生命周期编排：模块、存储与渠道能力随插件启停一并上线和回收。"""
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import pytest

from app.adapters.storage import StorageBase
from app.adapters.storage.registry import get_registered_storages, unregister_storages
from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_manager import PluginManager
from app.schemas.message import ChannelCapabilities, ChannelCapability, ChannelCapabilityManager
from app.schemas.types import MessageChannel, ModuleType

# 声明钩子在插件替身上要么给出返回值，要么整个摘除
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


class StubModule(_ModuleBase):
    """满足模块契约的最小实现"""

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


class StubStorage(StorageBase):
    """满足存储契约的最小实现"""

    schema = "stub_storage"
    transtype = {"copy": "复制"}

    def init_storage(self) -> None:
        pass

    def check(self) -> bool:
        return True

    def list(self, fileitem):
        return []

    def create_folder(self, fileitem, name: str):
        return None

    def get_folder(self, path):
        return None

    def get_item(self, path):
        return None

    def detail(self, fileitem):
        return None

    def delete(self, fileitem) -> bool:
        return True

    def rename(self, fileitem, name: str) -> bool:
        return True

    def download(self, fileitem, path=None):
        return None

    def upload(self, fileitem, path, new_name=None):
        return None

    def copy(self, fileitem, path, new_name: str) -> bool:
        return True

    def move(self, fileitem, path, new_name: str) -> bool:
        return True

    def link(self, fileitem, target_file) -> bool:
        return True

    def softlink(self, fileitem, target_file) -> bool:
        return True

    def usage(self):
        return None


STUB_CAPABILITIES = ChannelCapabilities(
    channel=MessageChannel.VoceChat,
    capabilities={ChannelCapability.INLINE_BUTTONS},
    max_buttons_per_row=1,
)


@pytest.fixture(autouse=True)
def module_base_configured():
    """按启动组合根的方式装配模块基类，用例结束后还原。"""
    previous = contract._module_base
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous


@pytest.fixture(autouse=True)
def clean_registries():
    """用例前后清空存储与渠道能力的外部注册，避免污染同进程内的其它用例。"""
    def purge():
        """回收本用例可能留下的全部外部注册"""
        for owner in set(ChannelCapabilityManager.get_registered_owners().values()):
            ChannelCapabilityManager.unregister_capabilities(owner)
        for owner in ("plugin_a", "plugin_a@beta", "plugin_b"):
            unregister_storages(owner)

    purge()
    yield
    purge()


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


def make_plugin_manager(key: str, plugin: Mock) -> PluginManager:
    """
    构造与全局单例隔离、只装一个实例的插件管理器

    :param key: 实例键
    :param plugin: 插件替身
    :return: 插件管理器
    """
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {key: object}
    plugin_manager._running_plugins = {key: plugin}
    return plugin_manager


def test_registering_extensions_brings_up_every_kind(manager):
    """插件上线时模块、存储与渠道能力一并注册。"""
    plugin = make_plugin("plugin_a",
                         provides_modules=[StubModule],
                         provides_storages=[StubStorage],
                         provides_channel_capabilities=[STUB_CAPABILITIES])
    plugin_manager = make_plugin_manager("plugin_a", plugin)

    with patched_module_manager(manager):
        plugin_manager._register_plugin_extensions("plugin_a")

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]
    assert StubStorage in get_registered_storages()
    assert ChannelCapabilityManager.get_max_buttons_per_row(MessageChannel.VoceChat) == 1


def test_unregistering_extensions_reclaims_every_kind(manager):
    """插件下线时模块、存储与渠道能力一并回收。"""
    plugin = make_plugin("plugin_a",
                         provides_modules=[StubModule],
                         provides_storages=[StubStorage],
                         provides_channel_capabilities=[STUB_CAPABILITIES])
    plugin_manager = make_plugin_manager("plugin_a", plugin)
    builtin_buttons_per_row = ChannelCapabilityManager.get_max_buttons_per_row(
        MessageChannel.VoceChat)

    with patched_module_manager(manager):
        plugin_manager._register_plugin_extensions("plugin_a")
        plugin_manager._unregister_plugin_extensions("plugin_a")

    assert manager.get_external_module_ids() == []
    assert StubStorage not in get_registered_storages()
    assert ChannelCapabilityManager.get_max_buttons_per_row(
        MessageChannel.VoceChat) == builtin_buttons_per_row


def test_reclaiming_one_kind_does_not_block_the_others(manager):
    """一类扩展点回收失败不得连累其余扩展点的回收。"""
    plugin = make_plugin("plugin_a",
                         provides_storages=[StubStorage],
                         provides_channel_capabilities=[STUB_CAPABILITIES])
    plugin_manager = make_plugin_manager("plugin_a", plugin)

    with patched_module_manager(manager):
        plugin_manager._register_plugin_extensions("plugin_a")
        with patch.object(PluginManager, "_unregister_module_owners",
                          side_effect=RuntimeError("boom")):
            plugin_manager._unregister_plugin_extensions("plugin_a")

    assert StubStorage not in get_registered_storages()
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_reregistration_is_idempotent(manager):
    """反复启停插件不得累积重复的扩展点注册。"""
    plugin = make_plugin("plugin_a",
                         provides_modules=[StubModule],
                         provides_storages=[StubStorage],
                         provides_channel_capabilities=[STUB_CAPABILITIES])
    plugin_manager = make_plugin_manager("plugin_a", plugin)

    with patched_module_manager(manager):
        for _ in range(3):
            plugin_manager._unregister_plugin_extensions("plugin_a")
            plugin_manager._register_plugin_extensions("plugin_a")

    assert manager.get_external_module_ids("plugin_a") == ["StubModule"]
    assert [storage for storage in get_registered_storages()
            if storage is StubStorage] == [StubStorage]
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: "plugin_a"
    }


def test_a_plugin_declaring_nothing_touches_no_registry():
    """没有任何声明的插件不触碰各注册中心。"""
    plugin_manager = make_plugin_manager("plugin_a", make_plugin("plugin_a"))

    with patch("app.runtime.extensions.plugin_manager.ModuleManager") as module_manager:
        plugin_manager._register_plugin_extensions()

    module_manager.assert_not_called()
    assert get_registered_storages() == []
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_a_disabled_instance_registers_nothing(manager):
    """未启用的实例不注册任何扩展点。"""
    plugin = make_plugin("plugin_a", state=False,
                         provides_modules=[StubModule],
                         provides_storages=[StubStorage],
                         provides_channel_capabilities=[STUB_CAPABILITIES])
    plugin_manager = make_plugin_manager("plugin_a", plugin)

    with patched_module_manager(manager):
        plugin_manager._register_plugin_extensions("plugin_a")

    assert manager.get_external_module_ids() == []
    assert get_registered_storages() == []
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_extensions_are_reclaimed_per_instance(manager):
    """回收一个分身实例的扩展点不影响同插件其余实例。"""
    default_plugin = make_plugin("plugin_a", provides_channel_capabilities=[STUB_CAPABILITIES])
    clone_plugin = make_plugin("plugin_a@beta", provides_storages=[StubStorage])
    plugin_manager = object.__new__(PluginManager)
    plugin_manager._plugins = {"plugin_a": object, "plugin_a@beta": object}
    plugin_manager._running_plugins = {
        "plugin_a": default_plugin,
        "plugin_a@beta": clone_plugin,
    }

    with patched_module_manager(manager):
        plugin_manager._register_plugin_extensions()
        plugin_manager._unregister_extension_owners(["plugin_a@beta"])

    assert StubStorage not in get_registered_storages()
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: "plugin_a"
    }
