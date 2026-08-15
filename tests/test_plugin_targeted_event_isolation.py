"""定向插件输入事件必须只落到开启会话的那一个实例。

``__mp_target_plugin_id`` 承载的是用户在私聊里键入的自由文本：同一插件类的其它分身
实例既不属于这次会话，也没有理由看到这段原文。定向粒度一旦退化到「类」，用户回复就会
被同类的每一个实例读到。
"""
from typing import Optional

import pytest

from app.chain.message import MessageChain
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.plugins import _PluginBase
from app.runtime.events import Event, eventmanager
from app.runtime.extensions.plugin_manager import PluginManager
from app.schemas.types import EventType

PLUGIN_ID = "TargetedInputPlugin"

# 事件落点，记录 (实例标识, 事件携带的用户原文)
RECEIVED: list = []


class TargetedInputPlugin(_PluginBase):
    """带插件输入处理方法的最小插件实现。"""

    plugin_name = "定向输入示例插件"
    plugin_version = "1.0"

    def init_plugin(self, config: dict = None):
        pass

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

    def on_message_action(self, event: Event) -> None:
        """把本实例读到的用户原文记入落点。"""
        RECEIVED.append((self.instance_id, (event.event_data or {}).get("input_text")))


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
def two_instances(monkeypatch):
    """让全局插件管理器上跑着该插件的默认实例与 alpha 分身。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {
        PLUGIN_ID: TargetedInputPlugin,
        f"{PLUGIN_ID}@alpha": TargetedInputPlugin,
    })
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            TargetedInputPlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
        f"{PLUGIN_ID}@alpha": PluginManager._instantiate_plugin(
            TargetedInputPlugin, PLUGIN_ID, "alpha"
        ),
    })
    return plugin_manager


def deliver(target_owner: Optional[str], text: str = "我的机场订阅密码") -> None:
    """按事件总线的内部调用路径投递一次定向的插件输入事件。"""
    eventmanager._EventManager__invoke_handler_by_type_sync(
        TargetedInputPlugin.on_message_action,
        Event(EventType.MessageAction, {"input_text": text}),
        True,
        target_owner,
    )


# --------------------------------------------------------------------------- #
# 事件总线的定向粒度
# --------------------------------------------------------------------------- #

def test_targeted_input_reaches_only_the_addressed_instance(two_instances):
    """定向到 alpha 的用户原文不得同时落到默认实例。"""
    deliver(f"{PLUGIN_ID}@alpha")

    assert RECEIVED == [("alpha", "我的机场订阅密码")]


def test_bare_plugin_id_target_resolves_to_the_default_instance(two_instances):
    """裸插件标识就是默认实例的实例键，不能被当成「该类全部实例」。"""
    deliver(PLUGIN_ID)

    assert RECEIVED == [(DEFAULT_INSTANCE_ID, "我的机场订阅密码")]


def test_explicit_default_instance_key_is_canonicalized(two_instances):
    """显式写出默认实例标识与裸标识等价，同样只命中默认实例。"""
    deliver(f"{PLUGIN_ID}@{DEFAULT_INSTANCE_ID}")

    assert RECEIVED == [(DEFAULT_INSTANCE_ID, "我的机场订阅密码")]


def test_unknown_instance_target_reaches_nobody(two_instances):
    """定向到已不存在的实例时宁可不投递，也不回落成广播。"""
    deliver(f"{PLUGIN_ID}@ghost")

    assert RECEIVED == []


def test_untargeted_event_still_reaches_every_instance(two_instances):
    """没有定向标记的广播事件维持原样，每个实例都要收到。"""
    deliver(None)

    assert sorted(instance_id for instance_id, _ in RECEIVED) == ["alpha", DEFAULT_INSTANCE_ID]


def test_single_instance_plugin_targeting_is_unchanged(monkeypatch):
    """存量单实例插件按裸标识定向的行为逐字节不变。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {PLUGIN_ID: TargetedInputPlugin})
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            TargetedInputPlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
    })

    deliver(PLUGIN_ID)

    assert RECEIVED == [(DEFAULT_INSTANCE_ID, "我的机场订阅密码")]


# --------------------------------------------------------------------------- #
# 会话登记的实例键
# --------------------------------------------------------------------------- #

def test_plugin_base_exposes_instance_key_for_session_registration():
    """插件作者登记会话时要拿得到实例键，默认实例退化为裸插件标识。"""
    default = PluginManager._instantiate_plugin(
        TargetedInputPlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
    )
    alpha = PluginManager._instantiate_plugin(TargetedInputPlugin, PLUGIN_ID, "alpha")

    assert default.instance_key == PLUGIN_ID
    assert alpha.instance_key == f"{PLUGIN_ID}@alpha"


@pytest.mark.parametrize("registered, expected", [
    ("DemoPlugin", "DemoPlugin"),
    ("DemoPlugin@default", "DemoPlugin"),
    ("DemoPlugin@alpha", "DemoPlugin@alpha"),
    ("DemoPlugin@..", "DemoPlugin@.."),
])
def test_session_owner_is_normalized_to_an_instance_key(registered, expected):
    """会话登记的插件标识一律归一成实例键，非法实例标识原样透传后不会命中任何实例。"""
    assert MessageChain._target_instance_key(registered) == expected
