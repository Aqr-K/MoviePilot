"""外部来源声明的渠道能力注册面测试。"""
import copy
import threading
from enum import Enum

import pytest

from app.schemas.message import (
    ChannelCapabilities,
    ChannelCapability,
    ChannelCapabilityManager,
)
from app.schemas.types import MessageChannel

# 内建渠道能力基线，用于校验注册面从不改动内建表
BUILTIN_BASELINE = copy.deepcopy(ChannelCapabilityManager._capabilities)


class _ExternalChannel(Enum):
    """内建表之外的渠道标识。"""

    Matrix = "Matrix"


def _make_capabilities(channel, **overrides) -> ChannelCapabilities:
    """
    构造一份渠道能力声明。
    :param channel: 渠道
    :param overrides: 覆盖的字段取值
    :return: 渠道能力
    """
    kwargs = {
        "channel": channel,
        "capabilities": {
            ChannelCapability.INLINE_BUTTONS,
            ChannelCapability.CALLBACK_QUERIES,
        },
        "max_buttons_per_row": 7,
        "max_button_rows": 9,
        "max_button_text_length": 11,
        "max_message_length": 1234,
        "fallback_enabled": False,
    }
    kwargs.update(overrides)
    return ChannelCapabilities(**kwargs)


@pytest.fixture(autouse=True)
def clean_registry():
    """
    每个用例前后清空外部注册状态，并校验内建表未被改动。
    """
    ChannelCapabilityManager._registered.clear()
    ChannelCapabilityManager._registered_owners.clear()
    yield
    ChannelCapabilityManager._registered.clear()
    ChannelCapabilityManager._registered_owners.clear()
    assert ChannelCapabilityManager._capabilities == BUILTIN_BASELINE


def test_registered_capabilities_visible_to_readonly_apis():
    """注册后所有只读查询立刻返回声明的取值。"""
    # Arrange
    declared = _make_capabilities(MessageChannel.Wechat)

    # Act
    accepted = ChannelCapabilityManager.register_capabilities(declared, "plugin-a")

    # Assert
    assert accepted is True
    assert ChannelCapabilityManager.get_capabilities(MessageChannel.Wechat) == declared
    assert ChannelCapabilityManager.get_max_message_length(MessageChannel.Wechat) == 1234
    assert ChannelCapabilityManager.get_max_buttons_per_row(MessageChannel.Wechat) == 7
    assert ChannelCapabilityManager.get_max_button_rows(MessageChannel.Wechat) == 9
    assert (
        ChannelCapabilityManager.get_max_button_text_length(MessageChannel.Wechat) == 11
    )
    assert ChannelCapabilityManager.should_use_fallback(MessageChannel.Wechat) is False
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }


def test_override_builtin_channel_grants_unsupported_capability():
    """覆盖内建渠道可以补上内建未声明的能力。"""
    # Arrange
    assert ChannelCapabilityManager.supports_buttons(MessageChannel.Wechat) is False
    assert ChannelCapabilityManager.supports_callbacks(MessageChannel.Wechat) is False

    # Act
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Wechat), "plugin-a"
    )

    # Assert
    assert ChannelCapabilityManager.supports_buttons(MessageChannel.Wechat) is True
    assert ChannelCapabilityManager.supports_callbacks(MessageChannel.Wechat) is True
    assert ChannelCapabilityManager.supports_markdown(MessageChannel.Wechat) is False


def test_override_builtin_channel_can_drop_capability():
    """覆盖内建渠道可以撤下内建已声明的能力。"""
    # Arrange
    assert ChannelCapabilityManager.supports_editing(MessageChannel.Telegram) is True

    # Act
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Telegram, capabilities=set()), "plugin-a"
    )

    # Assert
    assert ChannelCapabilityManager.supports_editing(MessageChannel.Telegram) is False
    assert ChannelCapabilityManager.supports_deletion(MessageChannel.Telegram) is False


def test_unregister_restores_builtin_values_exactly():
    """卸载后渠道能力精确回到内建基线。"""
    # Arrange
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Telegram), "plugin-a"
    )
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Feishu), "plugin-a"
    )

    # Act
    removed = ChannelCapabilityManager.unregister_capabilities("plugin-a")

    # Assert
    assert set(removed) == {MessageChannel.Telegram, MessageChannel.Feishu}
    for channel in (MessageChannel.Telegram, MessageChannel.Feishu):
        restored = ChannelCapabilityManager.get_capabilities(channel)
        assert restored == BUILTIN_BASELINE[channel]
        assert restored is ChannelCapabilityManager._capabilities[channel]
    assert ChannelCapabilityManager.get_max_message_length(MessageChannel.Telegram) == 3500
    assert ChannelCapabilityManager.supports_markdown(MessageChannel.Telegram) is True
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_unregister_unknown_owner_removes_nothing():
    """卸载未注册过的来源不影响既有注册。"""
    # Arrange
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Wechat), "plugin-a"
    )

    # Act
    removed = ChannelCapabilityManager.unregister_capabilities("plugin-b")

    # Assert
    assert removed == []
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }


def test_second_owner_cannot_take_registered_channel():
    """同一渠道被占用后其它来源的注册被拒绝，先到者保持生效。"""
    # Arrange
    first = _make_capabilities(MessageChannel.Wechat, max_message_length=100)
    second = _make_capabilities(MessageChannel.Wechat, max_message_length=200)
    assert ChannelCapabilityManager.register_capabilities(first, "plugin-a") is True

    # Act
    accepted = ChannelCapabilityManager.register_capabilities(second, "plugin-b")

    # Assert
    assert accepted is False
    assert ChannelCapabilityManager.get_capabilities(MessageChannel.Wechat) == first
    assert ChannelCapabilityManager.get_max_message_length(MessageChannel.Wechat) == 100
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }
    assert ChannelCapabilityManager.unregister_capabilities("plugin-b") == []


def test_same_owner_reregistration_is_idempotent_update():
    """同一来源重复注册为幂等更新，卸载一次即清空。"""
    # Arrange
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Wechat, max_message_length=100), "plugin-a"
    )
    updated = _make_capabilities(MessageChannel.Wechat, max_message_length=200)

    # Act
    accepted = ChannelCapabilityManager.register_capabilities(updated, "plugin-a")

    # Assert
    assert accepted is True
    assert ChannelCapabilityManager.get_capabilities(MessageChannel.Wechat) == updated
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }
    assert ChannelCapabilityManager.unregister_capabilities("plugin-a") == [
        MessageChannel.Wechat
    ]
    assert ChannelCapabilityManager.get_registered_owners() == {}
    assert (
        ChannelCapabilityManager.get_capabilities(MessageChannel.Wechat)
        == BUILTIN_BASELINE[MessageChannel.Wechat]
    )


@pytest.mark.parametrize(
    "capabilities, owner",
    [
        ("not-a-capabilities-object", "plugin-a"),
        (None, "plugin-a"),
        ({"channel": MessageChannel.Wechat}, "plugin-a"),
        (_make_capabilities(MessageChannel.Wechat), ""),
        (_make_capabilities(MessageChannel.Wechat), None),
        (_make_capabilities(MessageChannel.Wechat), "   "),
        (_make_capabilities(None), "plugin-a"),
    ],
)
def test_invalid_registration_rejected_without_state_change(capabilities, owner):
    """非法入参被拒绝且不产生任何注册状态。"""
    # Act
    accepted = ChannelCapabilityManager.register_capabilities(capabilities, owner)

    # Assert
    assert accepted is False
    assert ChannelCapabilityManager.get_registered_owners() == {}
    assert ChannelCapabilityManager._registered == {}
    assert (
        ChannelCapabilityManager.get_capabilities(MessageChannel.Wechat)
        == BUILTIN_BASELINE[MessageChannel.Wechat]
    )


@pytest.mark.parametrize("owner", ["", None, "   "])
def test_unregister_with_blank_owner_removes_nothing(owner):
    """空来源标识不会误删已有注册。"""
    # Arrange
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Wechat), "plugin-a"
    )

    # Act
    removed = ChannelCapabilityManager.unregister_capabilities(owner)

    # Assert
    assert removed == []
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }


def test_channel_outside_builtin_table_can_be_registered():
    """内建表没有的渠道也能注册，卸载后回到无记录状态。"""
    # Arrange
    declared = _make_capabilities(_ExternalChannel.Matrix)

    # Act
    accepted = ChannelCapabilityManager.register_capabilities(declared, "plugin-a")

    # Assert
    assert accepted is True
    assert ChannelCapabilityManager.get_capabilities(_ExternalChannel.Matrix) == declared
    assert ChannelCapabilityManager.supports_buttons(_ExternalChannel.Matrix) is True
    assert ChannelCapabilityManager.unregister_capabilities("plugin-a") == [
        _ExternalChannel.Matrix
    ]
    assert ChannelCapabilityManager.get_capabilities(_ExternalChannel.Matrix) is None
    assert ChannelCapabilityManager.get_max_buttons_per_row(_ExternalChannel.Matrix) == 2
    assert ChannelCapabilityManager.get_max_button_rows(_ExternalChannel.Matrix) == 5
    assert (
        ChannelCapabilityManager.get_max_button_text_length(_ExternalChannel.Matrix) == 20
    )
    assert ChannelCapabilityManager.get_max_message_length(_ExternalChannel.Matrix) == 0
    assert ChannelCapabilityManager.should_use_fallback(_ExternalChannel.Matrix) is True


def test_get_registered_owners_returns_detached_copy():
    """归属表对外返回副本，外部改动不影响内部状态。"""
    # Arrange
    ChannelCapabilityManager.register_capabilities(
        _make_capabilities(MessageChannel.Wechat), "plugin-a"
    )

    # Act
    owners = ChannelCapabilityManager.get_registered_owners()
    owners[MessageChannel.Telegram] = "plugin-x"
    owners.pop(MessageChannel.Wechat)

    # Assert
    assert ChannelCapabilityManager.get_registered_owners() == {
        MessageChannel.Wechat: "plugin-a"
    }


def test_concurrent_register_and_unregister_keeps_tables_consistent():
    """并发注册与卸载后覆盖表与归属表的键集合保持一致。"""
    # Arrange
    channels = list(MessageChannel)
    rounds = 40
    errors = []
    barrier = threading.Barrier(len(channels) * 2)

    def register_worker(channel, owner):
        try:
            barrier.wait()
            for _ in range(rounds):
                ChannelCapabilityManager.register_capabilities(
                    _make_capabilities(channel), owner
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def unregister_worker(owner):
        try:
            barrier.wait()
            for _ in range(rounds):
                ChannelCapabilityManager.unregister_capabilities(owner)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = []
    for index, channel in enumerate(channels):
        owner = f"plugin-{index}"
        threads.append(threading.Thread(target=register_worker, args=(channel, owner)))
        threads.append(threading.Thread(target=unregister_worker, args=(owner,)))

    # Act
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    # Assert
    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    registered = ChannelCapabilityManager._registered
    owners = ChannelCapabilityManager.get_registered_owners()
    assert set(registered.keys()) == set(ChannelCapabilityManager._registered_owners)
    assert set(registered.keys()) == set(owners.keys())
    for channel, capabilities in registered.items():
        assert capabilities.channel == channel
        assert owners[channel] == f"plugin-{channels.index(channel)}"
