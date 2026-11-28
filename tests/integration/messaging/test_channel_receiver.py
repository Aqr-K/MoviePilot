"""
实际 HTTP 与宿主 SDK 消费者的 owner 复核、保留身份及停机拒绝。
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.application.security import authorization
from app.schemas.channel import InteractionPolicy
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel
from app.sdk import channel as sdk


def _identity():
    """
    返回宿主已装配的合成连接元数据，不含平台凭据。
    """
    return dict(
        source="channel", channel=NotificationChannel.Telegram, connection_id="connection",
        provider="telegram", identity_namespace="namespace", parser_owner="TelegramModule", policy_revision=4,
    )



@pytest.mark.parametrize("field,value", [
    ("provider", "discord"), ("identity_namespace", "rebuilt"), ("parser_owner", "OtherModule"),
    ("policy_revision", 3), ("connection_id", "other-connection"),
])
def test_processing_rechecks_the_bound_owner_before_parsing(monkeypatch, field, value):
    """
    排队后处理仍复核当前连接、owner 和 revision，错误身份不能先调用解析器。
    """
    from app.chain.message import MessageChain

    config = NotificationConf(
        id="connection", name="channel", type="telegram", identity_namespace="namespace", enabled=True,
        interaction_policy=InteractionPolicy(
            connection_id="connection", identity_namespace="namespace", revision=4, enabled=True,
        ),
    )
    monkeypatch.setattr(authorization, "get_notification_configs", lambda: [config])
    monkeypatch.setattr("app.chain.message.get_channel_authorization", lambda: object())
    chain = MessageChain()
    parser = Mock()
    monkeypatch.setattr(chain, "run_module", parser)
    identity = _identity() | {field: value}
    chain.process_platform_payload(body=b"{}", **identity)
    parser.assert_not_called()



def test_legacy_plugin_parser_cannot_inject_proof_or_reserved_web_identity(monkeypatch):
    """
    旧公开解析 Hook 保留基础消息适配，私有证明会被丢弃，网页身份只能走登录入口。
    """
    import time

    from app.chain.message import MessageChain
    from app.domain.admission import AdmissionProof

    monkeypatch.setattr("app.chain.message.get_channel_authorization", lambda: object())
    monkeypatch.setattr("app.chain.message.get_notification_configs", lambda: [])
    chain = MessageChain()
    incoming = sdk.IncomingMessage(channel=NotificationChannel.Telegram, source="legacy", userid="alice", text="申请使用")
    incoming._admission_proof = AdmissionProof("connection", 4, "alice", None, time.time() + 60)
    monkeypatch.setattr(chain, "run_module", Mock(return_value=incoming))
    process = Mock()
    monkeypatch.setattr(chain, "process_incoming", process)
    chain.process(b"{}", None, {"source": "legacy", "_authenticated_sdk": True})
    assert incoming._admission_proof is None
    process.assert_called_once()
    assert "_authenticated_sdk" not in chain.run_module.call_args.kwargs["args"]
    process.reset_mock()
    incoming.channel = NotificationChannel.WebAgent
    chain.process(b"{}", None, {"source": "legacy"})
    process.assert_not_called()



@pytest.mark.parametrize("entry", ["http", "sdk"])
def test_stopped_message_chain_does_not_parse_or_process(entry, monkeypatch):
    """
    即使旧排队调用绕过提交边界，HTTP 和 SDK 消费者也在停机时封口。
    """
    from app.chain.message import MessageChain

    chain = MessageChain()
    monkeypatch.setattr(chain, "stop_state", SimpleNamespace(is_system_stopped=True))
    monkeypatch.setattr("app.chain.message.get_channel_authorization", lambda: object())
    parser = Mock()
    monkeypatch.setattr(chain, "run_module", parser)
    if entry == "http":
        chain.process(b"{}", None, {"source": "channel"})
    else:
        chain.process_platform_payload(body=b"{}", **_identity())
    parser.assert_not_called()



def test_disabled_http_connection_does_not_fall_back_to_plugin_parser(monkeypatch):
    """
    已知连接关闭交互后，兼容 HTTP 入口不能经其它解析器重新处理。
    """
    from app.chain.message import MessageChain

    chain = MessageChain()
    monkeypatch.setattr("app.chain.message.get_channel_authorization", lambda: object())
    monkeypatch.setattr("app.chain.message.get_notification_configs", lambda: [NotificationConf(
        name="disabled", type="telegram", enabled=True, interaction_enabled=False,
    )])
    parser = Mock()
    monkeypatch.setattr(chain, "run_module", parser)
    chain.process(b"{}", None, {"source": "disabled"})
    parser.assert_not_called()
