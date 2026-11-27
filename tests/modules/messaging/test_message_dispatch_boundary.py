"""
统一模块边界的私聊、连接重建隔离、功能选择及可信入口绑定。
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.application.messaging import ingress
from app.application.messaging.delivery import collect_notification_preflight
from app.application.security import authorization
from app.modules.telegram.module import TelegramModule
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel


@pytest.fixture
def module_connection(monkeypatch):
    """
    保留真实模块边界，只替换客户端和配置存储。

    :param monkeypatch: 自动恢复配置与客户端替身
    :return: 模块和有效连接
    """
    module = TelegramModule()
    module._channel = NotificationChannel.Telegram
    conf = NotificationConf(id="connection", identity_namespace="namespace", name="bot", type="telegram", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _name: conf)
    monkeypatch.setattr(module, "get_instance", lambda _name: None)
    return module, conf


def test_private_address_is_validated_and_cannot_inherit_group_context(module_connection):
    """
    强制私聊只接受个人地址，返回独立副本并清除群组、线程和编辑上下文。
    """
    module, _conf = module_connection
    message = Message(channel=NotificationChannel.Telegram, source="bot", userid="42", private_delivery=True,
                      original_chat_id="-100", thread_id="topic", original_message_id=7, force_reply=True)
    prepared = module.prepare_message(message)
    assert prepared is not message and prepared.userid == "42"
    assert prepared.original_chat_id is None and prepared.thread_id is None and prepared.original_message_id is None
    assert not prepared.force_reply and message.original_chat_id == "-100"
    for updates in ({"userid": "-100"}, {"channel": None}, {"source": None}, {"userid": None}):
        with pytest.raises(PermissionError):
            module.prepare_message(message.model_copy(update=updates))
    with pytest.raises(RuntimeError, match="不存在或已停用"):
        module.prepare_message(message.model_copy(update={"source": "removed"}))
    with pytest.raises(RuntimeError, match="未使用其他实例"):
        module.get_message_client("bot", prepared)
    assert module.get_message_client("bot", Message(text="普通消息")) is None


def test_delivery_semantics_choose_features_and_reject_rebuilt_connection(module_connection):
    """
    关闭事件通知不阻断交互回复，旧连接绑定不能进入同名新连接。
    """
    module, conf = module_connection
    conf.notification_enabled = False
    conf.interaction_enabled = True
    message = Message(channel=NotificationChannel.Telegram, source="bot", userid="42", text="正文")
    assert not module.check_message(message, "bot")
    reply = message.model_copy(update={"delivery_kind": "reply"})
    assert module.check_message(reply, "bot")
    reply.bind_delivery_connection("connection", "namespace")
    conf.identity_namespace = "replacement"
    assert not module.check_message(reply, "bot")
    conf.identity_namespace = "namespace"
    conf.interaction_enabled = False
    assert not module.check_message(reply, "bot")
    receipt = message.model_copy(update={"delivery_kind": "authorization_receipt"})
    assert module.check_message(receipt, "bot")
    conf.enabled = False
    assert not module.check_message(receipt, "bot")


def test_receipt_requires_real_confirmation_and_preflight_rejects_unavailable_client(module_connection):
    """
    失败不能被包装为私聊成功，预检发现客户端未就绪时不能冻结不完整计划。
    """
    module, conf = module_connection
    message = Message(channel=NotificationChannel.Telegram, source="bot", userid="42", text="正文")
    results = message.collect_delivery_results()
    with collect_notification_preflight(), pytest.raises(RuntimeError, match="尚未就绪"):
        module.record_delivery(message, conf, False, code="client_unavailable")
    assert results == []
    raw = {"success": True, "message_id": 12}
    assert module.record_delivery(message, conf, raw, target="42") is raw
    assert results[0].message_id == "12" and results[0].status == "confirmed"
    message.private_delivery = True
    with pytest.raises(RuntimeError, match="未回退"):
        module.record_delivery(message, conf, False, target="42")
    assert results[-1].status == "retryable_failure"


def test_host_bound_receiver_overrides_configured_injection(module_connection, monkeypatch):
    """
    配置与报文不能冒充宿主绑定的解析 owner、连接和身份空间。
    """
    module, conf = module_connection
    conf.config = {"message_ingress": "untrusted"}
    receiver, queued = Mock(), []
    monkeypatch.setattr(ingress, "_platform_payload_receiver", receiver)
    monkeypatch.setattr(ingress, "runtime_stop_state", SimpleNamespace(is_system_stopped=False))
    monkeypatch.setattr(authorization, "get_channel_authorization", lambda: object())
    bound = module._service_kwargs(conf)["message_ingress"]
    assert callable(bound)
    assert bound({"provider": "forged", "connection_id": "other"}, submit=lambda *args: queued.append(args))
    operation, *args = queued[0]
    operation(*args)
    assert receiver.call_args.args[1:7] == ("bot", NotificationChannel.Telegram, "connection", "telegram", "namespace", "TelegramModule")
