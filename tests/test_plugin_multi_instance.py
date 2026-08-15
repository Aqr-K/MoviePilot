"""同一插件类同时运行多个实例时的运行期隔离。

这一组的风险集中在「多出来的实例被静默吞掉」：容器键、模块标识、事件绑定任何一处仍按
插件类名寻址，第二个实例都不会报错，只是不干活；反过来，实例键如果不能对默认实例退化成
裸插件标识，全部存量单实例插件的键会一次性改名。
"""
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import pytest

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, PluginConfig
from app.db.models.plugindata import PluginData
from app.db.oper.pluginconfig import PluginConfigOper
from app.modules import _ModuleBase
from app.plugins import _PluginBase
from app.runtime.events import Event, eventmanager
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager, ProvidedModule
from app.runtime.extensions.plugin_instance import (
    instance_key,
    is_default_instance_key,
    plugin_id_of,
    qualify_module_id,
    split_instance_key,
)
from app.runtime.extensions.plugin_manager import PluginManager
from app.schemas.types import ChainEventType, ModuleType

PLUGIN_ID = "MultiInstancePlugin"

# 事件投递的落点，记录 (实例标识, 事件id)
RECEIVED: list = []


class MultiInstancePlugin(_PluginBase):
    """带事件处理方法的最小插件实现。"""

    plugin_name = "多实例示例插件"
    plugin_version = "1.0"

    def __init__(self):
        """官方插件的主流形态：自带无参构造并回调基类。"""
        super().__init__()
        self.inited_with = None

    def init_plugin(self, config: dict = None):
        self.inited_with = config

    def get_state(self) -> bool:
        return True

    def get_api(self):
        return []

    def get_form(self):
        return [], {}

    def get_page(self):
        return None

    def stop_service(self):
        pass

    def handle(self, event: Event) -> None:
        """把本实例的身份记入投递落点。"""
        RECEIVED.append((self.instance_id, event.event_id))


class IdentityAwarePlugin(MultiInstancePlugin):
    """构造期就需要用到身份的插件实现。"""

    def __init__(self, plugin_id: Optional[str] = None, instance_id: Optional[str] = None):
        """接受身份参数并在构造期记录。"""
        super(MultiInstancePlugin, self).__init__(plugin_id=plugin_id, instance_id=instance_id)
        self.identity_at_init = (self.plugin_id, self.instance_id)
        self.inited_with = None


class StubModule(_ModuleBase):
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


@pytest.fixture(autouse=True)
def _track(db):
    """把本文件涉及的表纳入用例级回收。"""
    db.watermark(PluginConfig, PluginData)


@pytest.fixture(autouse=True)
def _reset_received():
    """每个用例独享事件落点。"""
    RECEIVED.clear()
    yield
    RECEIVED.clear()


@pytest.fixture(autouse=True)
def _restore_event_switches():
    """用例结束后还原事件启停登记，避免污染全局事件总线。"""
    registries = {
        name: getattr(eventmanager, f"_EventManager__{name}")
        for name in ("disabled_handlers", "disabled_classes", "disabled_instances")
    }
    known = eventmanager._EventManager__known_instances
    snapshot = {name: set(value) for name, value in registries.items()}
    known_snapshot = {key: set(value) for key, value in known.items()}
    yield
    for name, registry in registries.items():
        registry.clear()
        registry.update(snapshot[name])
    known.clear()
    known.update(known_snapshot)


@pytest.fixture
def manager():
    """构造与全局单例隔离、容器为空的插件管理器。"""
    instance = object.__new__(PluginManager)
    instance._plugins = {}
    instance._running_plugins = {}
    return instance


@pytest.fixture
def module_manager():
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    previous = contract._module_base
    contract.configure_module_base(_ModuleBase)
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    yield instance
    contract._module_base = previous


def patched_module_manager(module_manager: ModuleManager):
    """让插件管理器取到指定的模块管理器实例，构造与查询两条取法都覆盖。"""
    stub = Mock(return_value=module_manager)
    stub.get_existing_instance.return_value = module_manager
    return patch("app.runtime.extensions.plugin_manager.ModuleManager", stub)


def running(manager: PluginManager, *instance_ids: str) -> dict:
    """在管理器中登记若干实例，返回 {实例标识: 插件实例}。"""
    instances = {}
    for instance_id in instance_ids:
        key = instance_key(PLUGIN_ID, instance_id)
        plugin = PluginManager._instantiate_plugin(MultiInstancePlugin, PLUGIN_ID, instance_id)
        manager._plugins[key] = MultiInstancePlugin
        manager._running_plugins[key] = plugin
        instances[instance_id] = plugin
    return instances


# --------------------------------------------------------------------------- #
# 实例键
# --------------------------------------------------------------------------- #

def test_default_instance_key_degrades_to_bare_plugin_id():
    """默认实例的实例键必须是裸插件标识，否则全部存量单实例插件的键一次性改名。"""
    assert instance_key("DemoPlugin") == "DemoPlugin"
    assert instance_key("DemoPlugin", None) == "DemoPlugin"
    assert instance_key("DemoPlugin", "") == "DemoPlugin"
    assert instance_key("DemoPlugin", DEFAULT_INSTANCE_ID) == "DemoPlugin"


def test_non_default_instance_key_is_composed():
    """非默认实例按分隔符合成，同插件的实例之间可区分。"""
    assert instance_key("DemoPlugin", "alpha") == "DemoPlugin@alpha"
    assert instance_key("DemoPlugin", "beta") == "DemoPlugin@beta"


def test_instance_key_rejects_illegal_instance_id():
    """实例标识非法时当场拒绝，不允许拼出越界的键。"""
    with pytest.raises(ValueError):
        instance_key("DemoPlugin", "a/b")


@pytest.mark.parametrize("plugin_id, instance_id", [
    ("DemoPlugin", DEFAULT_INSTANCE_ID),
    ("DemoPlugin", "alpha"),
    ("A_b0", "x-1"),
])
def test_instance_key_round_trips(plugin_id, instance_id):
    """合成与反解互逆，实例键上不会丢失任何一维身份。"""
    assert split_instance_key(instance_key(plugin_id, instance_id)) == (plugin_id, instance_id)


def test_split_instance_key_treats_bare_id_as_default_instance():
    """裸插件标识反解为默认实例。"""
    assert split_instance_key("DemoPlugin") == ("DemoPlugin", DEFAULT_INSTANCE_ID)
    assert plugin_id_of("DemoPlugin@alpha") == "DemoPlugin"
    assert is_default_instance_key("DemoPlugin") is True
    assert is_default_instance_key("DemoPlugin@alpha") is False


# --------------------------------------------------------------------------- #
# 实例化
# --------------------------------------------------------------------------- #

def test_plugin_with_no_arg_init_still_gets_identity():
    """插件自带无参 __init__ 是主流形态，直接传身份参数会 TypeError，身份必须由框架补齐。"""
    plugin = PluginManager._instantiate_plugin(MultiInstancePlugin, PLUGIN_ID, "alpha")

    assert plugin.plugin_id == PLUGIN_ID
    assert plugin.instance_id == "alpha"


def test_plugin_accepting_identity_receives_it_during_init():
    """__init__ 声明了身份参数时，构造期就能拿到身份。"""
    plugin = PluginManager._instantiate_plugin(IdentityAwarePlugin, "OriginPlugin", "beta")

    assert plugin.identity_at_init == ("OriginPlugin", "beta")
    assert plugin.plugin_id == "OriginPlugin"
    assert plugin.instance_id == "beta"


def test_default_instance_instantiation_keeps_legacy_identity():
    """默认实例的身份与不区分实例时完全一致。"""
    plugin = PluginManager._instantiate_plugin(MultiInstancePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID)

    assert (plugin.plugin_id, plugin.instance_id) == (PLUGIN_ID, DEFAULT_INSTANCE_ID)


# --------------------------------------------------------------------------- #
# 实例发现
# --------------------------------------------------------------------------- #

def test_plugin_without_any_configured_instance_starts_the_default_one():
    """一个实例都没配置时按默认实例拉起，未创建分身的插件行为保持不变。"""
    assert PluginManager._list_instance_ids(PLUGIN_ID) == [DEFAULT_INSTANCE_ID]


def test_configured_instances_are_all_discovered():
    """已配置的实例逐个拉起，不做去重之外的裁剪。"""
    oper = PluginConfigOper()
    oper.set(PLUGIN_ID, {"enable": True}, DEFAULT_INSTANCE_ID)
    oper.set(PLUGIN_ID, {"enable": True}, "alpha")

    assert sorted(PluginManager._list_instance_ids(PLUGIN_ID)) == ["alpha", DEFAULT_INSTANCE_ID]


def test_start_brings_up_every_configured_instance(manager, monkeypatch):
    """启动时每个已配置实例都进入容器，并各自吃到自己那份配置。"""
    oper = PluginConfigOper()
    oper.set(PLUGIN_ID, {"enable": True, "token": "default-token"}, DEFAULT_INSTANCE_ID)
    oper.set(PLUGIN_ID, {"enable": True, "token": "alpha-token"}, "alpha")
    monkeypatch.setattr(
        "app.runtime.extensions.plugin_manager.load_selective_plugins",
        lambda *_args, **_kwargs: [MultiInstancePlugin],
    )

    manager.start(PLUGIN_ID)

    assert sorted(manager.get_instance_keys(PLUGIN_ID)) == [PLUGIN_ID, f"{PLUGIN_ID}@alpha"]
    assert manager._running_plugins[PLUGIN_ID].inited_with["token"] == "default-token"
    assert manager._running_plugins[f"{PLUGIN_ID}@alpha"].inited_with["token"] == "alpha-token"


def test_start_without_configuration_keeps_the_bare_plugin_id_key(manager, monkeypatch):
    """未配置实例的插件仍以裸插件标识入容器，存量调用方按插件ID取实例不受影响。"""
    monkeypatch.setattr(
        "app.runtime.extensions.plugin_manager.load_selective_plugins",
        lambda *_args, **_kwargs: [MultiInstancePlugin],
    )

    manager.start(PLUGIN_ID)

    assert list(manager._running_plugins) == [PLUGIN_ID]
    assert manager.get_plugin_ids() == [PLUGIN_ID]
    assert manager.get_running_plugin_ids() == [PLUGIN_ID]


# --------------------------------------------------------------------------- #
# 配置与数据隔离
# --------------------------------------------------------------------------- #

def test_two_instances_of_one_class_do_not_share_config(manager):
    """同类双实例各写各的配置，读回不得串到对方那一行。"""
    instances = running(manager, DEFAULT_INSTANCE_ID, "alpha")

    instances[DEFAULT_INSTANCE_ID].update_config({"token": "default-token"})
    instances["alpha"].update_config({"token": "alpha-token"})

    assert instances[DEFAULT_INSTANCE_ID].get_config() == {"token": "default-token"}
    assert instances["alpha"].get_config() == {"token": "alpha-token"}
    assert manager.get_plugin_config(PLUGIN_ID, "alpha") == {"token": "alpha-token"}


def test_two_instances_of_one_class_do_not_share_data(manager):
    """同类双实例各写各的数据。"""
    instances = running(manager, DEFAULT_INSTANCE_ID, "alpha")

    instances[DEFAULT_INSTANCE_ID].save_data("state", {"v": "default"})
    instances["alpha"].save_data("state", {"v": "alpha"})

    assert instances[DEFAULT_INSTANCE_ID].get_data("state") == {"v": "default"}
    assert instances["alpha"].get_data("state") == {"v": "alpha"}


def test_manager_reaches_a_plugin_that_only_has_non_default_instances(manager):
    """插件只有分身实例时，按插件ID的存在性判定不能落空。"""
    running(manager, "alpha")

    assert manager.has_plugin(PLUGIN_ID) is True
    assert manager.get_plugin_ids() == [PLUGIN_ID]
    assert manager.get_plugin_config(PLUGIN_ID, "alpha") == {}


# --------------------------------------------------------------------------- #
# 事件投递
# --------------------------------------------------------------------------- #

def invoke_handler(event: Optional[Event] = None) -> None:
    """按事件总线的内部调用路径投递一次事件。"""
    eventmanager._EventManager__invoke_handler_by_type_sync(
        MultiInstancePlugin.handle, event or Event(ChainEventType.DiscoverSource)
    )


def test_every_running_instance_receives_the_event(monkeypatch):
    """同类双实例都要收到事件，只投递给字典序靠前的那个等于静默丢事件。"""
    plugin_manager = PluginManager()
    default_instance = PluginManager._instantiate_plugin(
        MultiInstancePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
    )
    alpha = PluginManager._instantiate_plugin(MultiInstancePlugin, PLUGIN_ID, "alpha")
    monkeypatch.setattr(plugin_manager, "_plugins", {
        PLUGIN_ID: MultiInstancePlugin,
        f"{PLUGIN_ID}@alpha": MultiInstancePlugin,
    })
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: default_instance,
        f"{PLUGIN_ID}@alpha": alpha,
    })

    invoke_handler()

    assert sorted(instance_id for instance_id, _ in RECEIVED) == ["alpha", DEFAULT_INSTANCE_ID]


def test_broadcast_event_data_is_isolated_between_instances(monkeypatch):
    """广播事件给每个实例独立的事件对象，一个实例改数据不会波及同类实例。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {
        PLUGIN_ID: MultiInstancePlugin,
        f"{PLUGIN_ID}@alpha": MultiInstancePlugin,
    })
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            MultiInstancePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
        f"{PLUGIN_ID}@alpha": PluginManager._instantiate_plugin(
            MultiInstancePlugin, PLUGIN_ID, "alpha"
        ),
    })
    event = Event(ChainEventType.DiscoverSource, {"seen": []})

    eventmanager._EventManager__invoke_handler_by_type_sync(
        MultiInstancePlugin.handle, event, True
    )

    assert len({event_id for _, event_id in RECEIVED}) == 2


def test_single_instance_event_delivery_is_unchanged(monkeypatch):
    """单实例插件仍然只被投递一次。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {PLUGIN_ID: MultiInstancePlugin})
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            MultiInstancePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
    })

    invoke_handler()

    assert [instance_id for instance_id, _ in RECEIVED] == [DEFAULT_INSTANCE_ID]


def test_event_handlers_can_be_switched_off_per_instance(monkeypatch):
    """按实例启停：停掉一个实例的事件后，同类的其他实例照常收事件。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {
        PLUGIN_ID: MultiInstancePlugin,
        f"{PLUGIN_ID}@alpha": MultiInstancePlugin,
    })
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            MultiInstancePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
        f"{PLUGIN_ID}@alpha": PluginManager._instantiate_plugin(
            MultiInstancePlugin, PLUGIN_ID, "alpha"
        ),
    })

    eventmanager.disable_event_handler(MultiInstancePlugin, f"{PLUGIN_ID}@alpha")
    invoke_handler()

    assert [instance_id for instance_id, _ in RECEIVED] == [DEFAULT_INSTANCE_ID]


def test_class_is_reported_disabled_only_when_no_instance_is_left():
    """只要还有一个实例启用，该类就仍被视为可投递；全部实例停用后才判定为不可投递。"""
    is_enabled = eventmanager._EventManager__is_handler_enabled
    # 插件加载时会为每个实例登记启停状态，这里按同样的顺序铺开
    eventmanager.enable_event_handler(MultiInstancePlugin, PLUGIN_ID)
    eventmanager.enable_event_handler(MultiInstancePlugin, f"{PLUGIN_ID}@alpha")

    eventmanager.disable_event_handler(MultiInstancePlugin, f"{PLUGIN_ID}@alpha")
    assert is_enabled(MultiInstancePlugin.handle) is True

    eventmanager.disable_event_handler(MultiInstancePlugin, PLUGIN_ID)
    assert is_enabled(MultiInstancePlugin.handle) is False

    eventmanager.enable_event_handler(MultiInstancePlugin, PLUGIN_ID)
    assert is_enabled(MultiInstancePlugin.handle) is True


# --------------------------------------------------------------------------- #
# 注册式模块
# --------------------------------------------------------------------------- #

def test_single_instance_module_id_degrades_to_the_bare_class_name(module_manager):
    """默认实例注册的模块保持裸类名，与内建模块零冲突。"""
    assert module_manager.register_module(StubModule, owner=PLUGIN_ID) is True

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubModule"]
    assert module_manager.get_running_module("StubModule") is not None


def test_two_instances_registering_one_class_do_not_collide(module_manager):
    """同一模块类被两个实例注册时不得互相顶掉，两条声明都要上线。"""
    assert module_manager.register_module(StubModule, owner=PLUGIN_ID) is True
    assert module_manager.register_module(StubModule, owner=f"{PLUGIN_ID}@alpha") is True

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubModule"]
    assert module_manager.get_external_module_ids(f"{PLUGIN_ID}@alpha") == [
        f"StubModule@{PLUGIN_ID}@alpha"
    ]
    assert len(list(module_manager.get_running_modules("stub_capability"))) == 2


def test_explicit_module_id_is_also_qualified_per_instance(module_manager):
    """显式声明的模块标识同样按实例限定，否则两个实例仍会撞在一起。"""
    module_manager.register_module(
        ProvidedModule(StubModule, module_id="shared"), owner=PLUGIN_ID
    )
    module_manager.register_module(
        ProvidedModule(StubModule, module_id="shared"), owner=f"{PLUGIN_ID}@alpha"
    )

    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["shared"]
    assert module_manager.get_external_module_ids(f"{PLUGIN_ID}@alpha") == [
        f"shared@{PLUGIN_ID}@alpha"
    ]


def test_qualify_module_id_keeps_default_instances_bare():
    """限定函数本身对默认实例退化。"""
    assert qualify_module_id("StubModule", PLUGIN_ID) == "StubModule"
    assert qualify_module_id("StubModule", f"{PLUGIN_ID}@alpha") == f"StubModule@{PLUGIN_ID}@alpha"


def test_module_events_reach_every_registered_instance(module_manager):
    """同一模块类的多份注册都要拿到事件绑定。"""
    module_manager.register_module(StubModule, owner=PLUGIN_ID)
    module_manager.register_module(StubModule, owner=f"{PLUGIN_ID}@alpha")

    bindings = module_manager.resolve_event_handler_instances(StubModule)

    assert sorted(binding.instance_key for binding in bindings) == [
        "StubModule", f"StubModule@{PLUGIN_ID}@alpha"
    ]


# --------------------------------------------------------------------------- #
# 单实例下线
# --------------------------------------------------------------------------- #

def test_stopping_one_instance_keeps_the_others_running(manager, module_manager):
    """停一个实例只回收它自己的注册来源，同插件其余实例不受牵连。"""
    instances = running(manager, DEFAULT_INSTANCE_ID, "alpha")
    with patched_module_manager(module_manager):
        module_manager.register_module(StubModule, owner=PLUGIN_ID)
        module_manager.register_module(StubModule, owner=f"{PLUGIN_ID}@alpha")

        manager.stop(PLUGIN_ID, "alpha")

    assert manager.get_instance_keys(PLUGIN_ID) == [PLUGIN_ID]
    assert manager._running_plugins[PLUGIN_ID] is instances[DEFAULT_INSTANCE_ID]
    assert module_manager.get_external_module_ids(f"{PLUGIN_ID}@alpha") == []
    assert module_manager.get_external_module_ids(PLUGIN_ID) == ["StubModule"]
    assert module_manager.get_running_module("StubModule") is not None


def test_stopping_a_plugin_takes_down_all_of_its_instances(manager, module_manager):
    """按插件ID停止时，该插件的全部实例一并下线。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    with patched_module_manager(module_manager):
        module_manager.register_module(StubModule, owner=PLUGIN_ID)
        module_manager.register_module(StubModule, owner=f"{PLUGIN_ID}@alpha")

        manager.stop(PLUGIN_ID)

    assert manager.get_instance_keys(PLUGIN_ID) == []
    assert module_manager.get_external_module_ids() == []


def test_database_is_not_disposed_while_another_instance_runs(manager, monkeypatch):
    """同插件多个实例共享一个库，还有实例在跑时不得释放连接。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    disposed = []
    monkeypatch.setattr("app.db.plugin.db_manager", Mock(dispose=disposed.append))

    with patch("app.runtime.extensions.plugin_manager.ModuleManager") as module_manager:
        module_manager.get_existing_instance.return_value = None
        manager.remove_plugin(PLUGIN_ID, "alpha")

    assert disposed == []
    assert manager.get_instance_keys(PLUGIN_ID) == [PLUGIN_ID]


def test_database_is_disposed_once_the_last_instance_goes(manager, monkeypatch):
    """最后一个实例下线才释放连接。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    disposed = []
    monkeypatch.setattr("app.db.plugin.db_manager", Mock(dispose=disposed.append))

    with patch("app.runtime.extensions.plugin_manager.ModuleManager") as module_manager:
        module_manager.get_existing_instance.return_value = None
        manager.remove_plugin(PLUGIN_ID, "alpha")
        manager.remove_plugin(PLUGIN_ID, DEFAULT_INSTANCE_ID)

    assert disposed == [PLUGIN_ID]
    assert manager.has_plugin(PLUGIN_ID) is False
