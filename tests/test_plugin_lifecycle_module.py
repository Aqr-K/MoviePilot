"""插件扩展点注册与回收函数的行为。

直接针对 ``app.runtime.extensions.plugin_lifecycle`` 的公开函数：各类扩展点随实例键上线与
回收、按注册来源精确回收、以及一类扩展点回收失败不连累其余。存储是系统模块的一种，与
下载器、媒体服务器走同一条注册通道。
"""
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import pytest

from app.modules.storages.base import StorageBase
from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_lifecycle import (
    extension_owners,
    reclaim_extension_owners,
    register_plugin_channel_capabilities,
    register_plugin_extensions,
    register_plugin_modules,
    unregister_capability_owners,
    unregister_module_owners,
)
from app.schemas.message import ChannelCapabilities, ChannelCapability, ChannelCapabilityManager
from app.schemas.types import MessageChannel, ModuleType

PLUGIN_ID = "lifecycle_plugin"
CLONE_KEY = f"{PLUGIN_ID}@beta"
OTHER_PLUGIN_ID = "other_lifecycle_plugin"

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

    schema = "lifecycle_stub_storage"
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
    """用例前后清空渠道能力的全局注册，避免污染同进程内的其它用例。"""
    def purge():
        """回收本用例可能留下的全部全局注册"""
        for owner in set(ChannelCapabilityManager.get_registered_owners().values()):
            ChannelCapabilityManager.unregister_capabilities(owner)

    purge()
    yield
    purge()


@pytest.fixture
def module_manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    return instance


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


def full_plugin(plugin_id: str, **kwargs) -> Mock:
    """
    构造三类扩展点齐全的插件替身

    :param plugin_id: 插件标识
    :param kwargs: 透传给 make_plugin 的其余参数
    :return: 插件替身
    """
    return make_plugin(plugin_id,
                       provides_modules=[StubModule],
                       provides_storages=[StubStorage],
                       provides_channel_capabilities=[STUB_CAPABILITIES],
                       **kwargs)


# --------------------------------------------------------------------------- 注册


def test_registering_brings_up_every_kind(module_manager):
    """注册扩展点时模块、存储与渠道能力一并上线。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID)}

    register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    assert sorted(module_manager.get_external_module_ids(PLUGIN_ID)) == ["StubModule", "StubStorage"]
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: PLUGIN_ID
    }


def test_registering_without_a_filter_covers_every_running_instance(module_manager):
    """不指定插件时全部运行态实例的声明都要注册。"""
    running = {
        PLUGIN_ID: make_plugin(PLUGIN_ID, provides_channel_capabilities=[STUB_CAPABILITIES]),
        CLONE_KEY: make_plugin(CLONE_KEY, provides_storages=[StubStorage]),
    }

    register_plugin_extensions(running, lambda: module_manager)

    assert module_manager.get_external_module_ids(CLONE_KEY) != []
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: PLUGIN_ID
    }


def test_registering_is_scoped_to_the_requested_plugin(module_manager):
    """指定插件时其余插件的声明不被注册。"""
    running = {
        PLUGIN_ID: make_plugin(PLUGIN_ID, provides_storages=[StubStorage]),
        OTHER_PLUGIN_ID: make_plugin(OTHER_PLUGIN_ID,
                                     provides_channel_capabilities=[STUB_CAPABILITIES]),
    }

    register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubStorage"]
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_registering_modules_without_declarations_skips_the_module_manager():
    """没有插件声明模块时不取模块管理器，避免提前触发模块全量装载。"""
    running = {PLUGIN_ID: make_plugin(PLUGIN_ID)}
    factory = Mock()

    register_plugin_modules(running, factory)

    factory.assert_not_called()


def test_a_declared_storage_registers_as_a_module(module_manager):
    """存储声明按系统模块登记，与通用模块声明并列。"""
    running = {PLUGIN_ID: make_plugin(PLUGIN_ID, provides_storages=[StubStorage])}

    register_plugin_modules(running, lambda: module_manager, PLUGIN_ID)

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubStorage"]
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_a_disabled_instance_registers_nothing(module_manager):
    """未启用的实例不注册任何扩展点。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID, state=False)}

    register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    assert module_manager.get_external_module_ids() == []
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_registering_is_idempotent(module_manager):
    """反复注册不得累积重复的扩展点。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID)}

    for _ in range(3):
        register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    assert sorted(module_manager.get_external_module_ids(PLUGIN_ID)) == ["StubModule", "StubStorage"]
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: PLUGIN_ID
    }


def test_a_rejected_capability_is_reported(module_manager):
    """渠道能力未被接受时给出告警，其余声明照常处理。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID)}

    with patch.object(ChannelCapabilityManager, "register_capabilities", return_value=False), \
            patch("app.runtime.extensions.plugin_lifecycle.logger") as lifecycle_logger:
        register_plugin_channel_capabilities(running, PLUGIN_ID)

    assert lifecycle_logger.warning.call_count == 1


# --------------------------------------------------------------------------- 回收


def test_reclaiming_takes_down_every_kind(module_manager):
    """回收注册来源时模块、存储与渠道能力一并下线。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID)}
    register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    reclaim_extension_owners([PLUGIN_ID], (
        lambda owners: unregister_module_owners(owners, lambda: module_manager),
        unregister_capability_owners,
    ))

    assert module_manager.get_external_module_ids() == []
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_reclaiming_is_scoped_to_the_given_owner(module_manager):
    """回收一个分身实例不影响同插件其余实例的注册。"""
    running = {
        PLUGIN_ID: make_plugin(PLUGIN_ID, provides_channel_capabilities=[STUB_CAPABILITIES]),
        CLONE_KEY: make_plugin(CLONE_KEY, provides_storages=[StubStorage]),
    }
    register_plugin_extensions(running, lambda: module_manager)

    unregister_module_owners([CLONE_KEY], lambda: module_manager)
    unregister_capability_owners([CLONE_KEY])

    assert module_manager.get_external_module_ids(CLONE_KEY) == []
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.VoceChat: PLUGIN_ID
    }


def test_reclaiming_modules_is_scoped_to_the_given_owner(module_manager):
    """按注册来源回收模块，其余来源的同名声明不受影响。"""
    module_manager.register_module(StubModule, owner=PLUGIN_ID)
    module_manager.register_module(StubModule, owner=CLONE_KEY)

    unregister_module_owners([CLONE_KEY], lambda: module_manager)

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubModule"]
    assert module_manager.get_external_module_ids(CLONE_KEY) == []


def test_reclaiming_modules_without_a_module_manager_is_a_no_op():
    """模块管理器尚未装载时无模块可回收，不得反向触发其装载。"""
    unregister_module_owners([PLUGIN_ID], lambda: None)


def test_one_failing_kind_does_not_block_the_others(module_manager):
    """一类扩展点回收失败不得连累其余扩展点的回收。"""
    running = {PLUGIN_ID: full_plugin(PLUGIN_ID)}
    register_plugin_extensions(running, lambda: module_manager, PLUGIN_ID)

    def exploding(_owners):
        """必定失败的回收动作"""
        raise RuntimeError("boom")

    reclaim_extension_owners([PLUGIN_ID], (
        exploding,
        unregister_capability_owners,
    ))

    assert ChannelCapabilityManager.get_registered_owners() == {}
    assert sorted(module_manager.get_external_module_ids(PLUGIN_ID)) == ["StubModule", "StubStorage"]


def test_every_reclaimer_runs_even_when_all_of_them_fail():
    """全部回收动作失败时仍逐个执行完，不在首个异常处中断。"""
    attempted = []

    def exploding(owners):
        """记录一次尝试后失败的回收动作"""
        attempted.append(owners)
        raise RuntimeError("boom")

    reclaim_extension_owners([PLUGIN_ID], (exploding, exploding, exploding))

    assert attempted == [[PLUGIN_ID]] * 3


# --------------------------------------------------------------------------- 注册来源


def test_owners_cover_both_containers():
    """未指定插件时注册来源取插件类表与运行态表的并集。"""
    plugins = {PLUGIN_ID: object, CLONE_KEY: object}
    running = {CLONE_KEY: object(), OTHER_PLUGIN_ID: object()}

    assert extension_owners(plugins, running) == [PLUGIN_ID, CLONE_KEY, OTHER_PLUGIN_ID]


def test_owners_of_a_plugin_cover_all_of_its_instances():
    """指定插件时取该插件的全部实例键，其余插件不在其中。"""
    plugins = {PLUGIN_ID: object, CLONE_KEY: object, OTHER_PLUGIN_ID: object}

    assert extension_owners(plugins, {}, PLUGIN_ID) == [PLUGIN_ID, CLONE_KEY]


def test_owners_fall_back_to_the_default_instance_key():
    """插件加载失败未进入任何容器时，按其默认实例键回收可能残留的注册。"""
    assert extension_owners({}, {}, PLUGIN_ID) == [PLUGIN_ID]


def test_owners_are_empty_when_nothing_is_loaded():
    """没有任何已登记实例且未指定插件时无需回收。"""
    assert extension_owners({}, {}) == []
