"""
统一回执对局部失败、静默失败和未确认的发送给出不同结果。
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import unquote

import discord
import pytest

from app.adapters.network.webpush import WebPushDeliveryError
from app.application.messaging.delivery import (
    NotificationParts,
    claim_notification_part,
    delivery_status,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.application.webpush import WebPushRegistration
from app.modules.apppush import AppPushModule
from app.modules.dingtalk import DingTalkModule
from app.modules.discord import DiscordModule
from app.modules.discord.discord import Discord
from app.modules.feishu.feishu import Feishu
from app.modules.feishu.module import FeishuModule
from app.modules.qqbot.module import QQBotModule
from app.modules.slack import SlackModule
from app.modules.slack.slack import Slack
from app.modules.synologychat import SynologyChatModule
from app.modules.synologychat.synologychat import SynologyChat
from app.modules.telegram.botapi import TelegramApiError, TelegramNetworkError
from app.modules.telegram.module import TelegramModule
from app.modules.telegram.telegram import Telegram
from app.modules.vocechat import VoceChatModule
from app.modules.vocechat.vocechat import VoceChat
from app.modules.webpush import WebPushModule
from app.modules.wechat import WechatModule
from app.modules.wechatclawbot import WechatClawBotModule
from app.modules.wechatclawbot.wechatclawbot import WechatClawBot
from app.runtime.correlation import correlation_scope
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType, NotificationChannel


@pytest.mark.parametrize("module_type,channel,provider,provider_config", [
    (DingTalkModule, NotificationChannel.DingTalk, "dingtalk", {}),
    (DiscordModule, NotificationChannel.Discord, "discord", {}),
    (FeishuModule, NotificationChannel.Feishu, "feishu", {}),
    (QQBotModule, NotificationChannel.QQ, "qqbot", {}),
    (SlackModule, NotificationChannel.Slack, "slack", {}),
    (SynologyChatModule, NotificationChannel.SynologyChat, "synologychat", {}),
    (TelegramModule, NotificationChannel.Telegram, "telegram", {}),
    (VoceChatModule, NotificationChannel.VoceChat, "vocechat", {}),
    (WechatModule, NotificationChannel.Wechat, "wechat", {"WECHAT_MODE": "app"}),
    (WechatModule, NotificationChannel.Wechat, "wechat", {"WECHAT_MODE": "bot"}),
    (WechatClawBotModule, NotificationChannel.WechatClawBot, "wechatclawbot", {}),
])
def test_provider_reports_client_unavailable(monkeypatch, module_type, channel, provider, provider_config):
    """
    活跃配置指向尚未就绪的客户端时，派发回执保留连接和可重试状态。
    """
    module = module_type()
    module._channel = channel
    conf = NotificationConf(id="original", name="fixture", type=provider, enabled=True, config=provider_config,
                            identity_namespace="binding")
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    monkeypatch.setattr(module, "get_instance", lambda _: None)
    message = Message(channel=channel, source=conf.name, userid="user:42", text="正文")
    receipts = message.collect_delivery_results()

    if channel == NotificationChannel.Telegram:
        with pytest.raises(RuntimeError, match="通知发送未确认"):
            module.post_message(message)
    else:
        module.post_message(message)

    result, = receipts
    assert (result.connection_id, result.identity_namespace, result.status, result.code) == (
        "original", "binding", "retryable_failure", "client_unavailable",
    )


@pytest.mark.parametrize("channel,owner,service_available,expected", [
    (NotificationChannel.WebPush, None, False, ("skipped", "no_target")),
    (NotificationChannel.WebPush, "owner", False, ("retryable_failure", "client_unavailable")),
    (NotificationChannel.WebPush, "owner", True, ("skipped", "no_device")),
    (NotificationChannel.AppPush, None, False, ("skipped", "no_target")),
])
def test_push_receipt_distinguishes_no_target_no_device_and_unavailable_service(
    monkeypatch, channel, owner, service_available, expected,
):
    """
    账号和设备为空时不投递，明确目标的推送服务未就绪时报告可重试。
    """
    module = WebPushModule() if channel == NotificationChannel.WebPush else AppPushModule()
    module._channel = channel
    conf = NotificationConf(id="push", name="fixture", type=channel.value.lower(), enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    lookup = Mock(return_value=SimpleNamespace(for_owners=Mock(return_value=())))
    if not service_available:
        lookup.side_effect = RuntimeError("服务未就绪")
    monkeypatch.setattr("app.modules.webpush.get_webpush_service", lookup)
    send = Mock()
    monkeypatch.setattr("app.modules.webpush.send_webpush", send)
    monkeypatch.setattr(AppPushModule, "_request", send)
    message = Message(channel=channel, source=conf.name, title="通知",
                      targets={conf.type: owner} if owner else None)
    message.set_notification_route_scope("all")
    receipts = message.collect_delivery_results()

    module.post_message(message)

    result, = receipts
    assert (result.status, result.code) == expected
    assert lookup.call_count == int(channel == NotificationChannel.WebPush and owner is not None)
    send.assert_not_called()


@pytest.mark.parametrize("provider,channel,client_type,module_type", [
    ("discord", NotificationChannel.Discord, Discord, DiscordModule),
    ("feishu", NotificationChannel.Feishu, Feishu, FeishuModule),
    ("slack", NotificationChannel.Slack, Slack, SlackModule),
])
def test_ordinary_adapter_dispatch_does_not_reuse_an_unrelated_notification_key(
    monkeypatch, provider, channel, client_type, module_type,
):
    """
    两次共用调用关联 ID 的正常发送各自提交，并保留实际分段的平台消息标识。
    """
    client = object.__new__(client_type)
    if provider == "discord":
        client._loop = Mock()
        client.get_state = Mock(return_value=True)
        destination = Mock(spec=discord.abc.Messageable, id=12)
        client._resolve_channel = AsyncMock(return_value=destination)
        resolved = Mock(**{"result.return_value": destination})

        def resolve(coroutine, _loop):
            """
            隔离 Discord 线程并返回指定频道。
            """
            coroutine.close()
            return resolved

        monkeypatch.setattr("app.modules.discord.discord.asyncio.run_coroutine_threadsafe", resolve)
        submit = Mock(return_value=("confirmed", None, "fixture-message"))
        client._submit_tracked_part = submit
    elif provider == "feishu":
        submit = Mock(return_value=("confirmed", None, "fixture-message"))
        client._submit_tracked_message = submit
        client._resolve_target = Mock(return_value=("C1", "chat_id"))
    else:
        submit = Mock(return_value={"ok": True, "ts": "fixture-message"})
        client._notification_client = SimpleNamespace(chat_postMessage=submit)

    conf = NotificationConf(id=provider, name=provider, type=provider, enabled=True)
    module = module_type()
    module._channel = channel
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    with correlation_scope("fixture-shared-correlation"):
        for body in ("第一条正文", "第二条正文"):
            message = Message(channel=channel, source=conf.name, userid="C1", text=body)
            receipts = message.collect_delivery_results()
            module.post_message(message)
            receipt, = receipts
            assert (receipt.status, receipt.message_id) == ("confirmed", "fixture-message")

    first, second = submit.call_args_list
    if provider in {"discord", "feishu"}:
        assert first.args[3] != second.args[3]
    else:
        assert [first.kwargs["text"], second.kwargs["text"]] == ["第一条正文", "第二条正文"]


def _observe_recovery(state, *, initial):
    """
    让真实分段算法将内存字典作为独立通知意图的进度存储。
    """
    def record(results):
        """
        合并新回执，并保留已确认的记录。
        """
        state.update(merge_notification_progress(state, results))

    def reserve(part, should_submit):
        """
        按本次派发所处阶段保护网络提交。
        """
        recorded, updated = claim_notification_part(
            state, part, initial_attempt=initial, should_submit=should_submit,
        )
        state.update(updated)
        return recorded

    def plan(parts):
        """
        仅首次派发记录目标。
        """
        if initial:
            state.update(freeze_notification_parts(state, parts))

    return observe_notification_progress(record, reserve=reserve, plan=plan)


def test_webpush_resumes_only_original_subscription_version(monkeypatch):
    """
    恢复时不重发到已确认设备，不发送到新增、重新登记或临近发送时被撤销的设备。
    """
    def registration(name, revision="v1"):
        """
        生成具有确定账号和登记版本的设备。
        """
        return WebPushRegistration(f"https://push.example/{name}", "key", "secret", 1, "alice", revision)

    devices = [registration(name) for name in ("sent", "limited", "changed", "removed")]
    service = SimpleNamespace(for_owners=lambda _: tuple(devices), is_current=Mock(return_value=True))
    monkeypatch.setattr("app.modules.webpush.get_webpush_service", lambda: service)
    status = SimpleNamespace(status_code=429, headers={"Retry-After": "17"})
    send = Mock(side_effect=[None, WebPushDeliveryError("limit", status),
                            WebPushDeliveryError("limit", status), WebPushDeliveryError("limit", status), None])
    monkeypatch.setattr("app.modules.webpush.send_webpush", send)
    conf = NotificationConf(id="web", name="web", type="webpush", enabled=True, identity_namespace="binding")
    module = WebPushModule()
    module._channel = NotificationChannel.WebPush
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    message = Message(channel=NotificationChannel.WebPush, title="完成", targets={"webpush": "alice"})
    message.set_notification_route_scope("user")
    results = message.collect_delivery_results()
    progress = {}
    with _observe_recovery(progress, initial=True):
        module.post_message(message)
    assert [(item.status, item.retry_after) for item in results] == [
        ("confirmed", None), ("retryable_failure", 17), ("retryable_failure", 17), ("retryable_failure", 17),
    ]
    devices[2] = registration("changed", "v2")
    devices.append(registration("new"))
    service.is_current.side_effect = lambda item: item.endpoint.rsplit("/", 1)[-1] != "removed"
    results.clear()
    with _observe_recovery(progress, initial=False):
        module.post_message(message)
    assert [(item.status, item.code) for item in results] == [
        ("confirmed", None), ("confirmed", None), ("permanent_failure", "unplanned_target"),
        ("skipped", "subscription_changed"), ("permanent_failure", "unplanned_target"),
    ]
    assert [call.kwargs["subscription"]["endpoint"].rsplit("/", 1)[-1] for call in send.call_args_list] == [
        "sent", "limited", "changed", "removed", "limited",
    ]






@pytest.mark.parametrize("provider,channel,client_type,module_type", [
    ("vocechat", NotificationChannel.VoceChat, VoceChat, VoceChatModule),
    ("synologychat", NotificationChannel.SynologyChat, SynologyChat, SynologyChatModule),
])
@pytest.mark.parametrize("status,expected", [
    (None, "unknown"), (200, "confirmed"), (403, "permanent_failure"), (429, "retryable_failure"),
])
def test_chat_adapter_reports_the_same_receipt_for_normal_and_managed_delivery(
    monkeypatch, provider, channel, client_type, module_type, status, expected,
):
    """
    实际客户端在普通派发与受管派发中保留相同目标、正文和确认结果。
    """
    client = object.__new__(client_type)
    response = Mock(status_code=status)
    response.json.return_value = {"success": True}
    request = Mock()
    request.post_res.return_value = response if status is not None else None
    if provider == "vocechat":
        client._client = request
        client._host = "https://fixture.example/"
        client._channel_id = "77"
    else:
        client._req = request
        client._token = "synthetic"
        client._webhook_url = "https://fixture.example/chat"

    module = module_type()
    module._channel = channel
    config = NotificationConf(id=provider, name=provider, type=provider, enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {provider: config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    message = Message(channel=channel, source=provider, userid="42", text="仅正文")
    scoped = message.model_copy(deep=True)
    receipts = message.collect_delivery_results()
    module.post_message(message)
    assert len(receipts) == 1
    assert receipts[0].status == expected and receipts[0].target_id.endswith(":42")
    first_request = request.post_res.call_args
    if provider == "vocechat":
        assert first_request.args[0].endswith("/api/bot/send_to_user/42")
        assert first_request.kwargs["data"].decode() == "仅正文"
    else:
        payload = json.loads(first_request.kwargs["data"].removeprefix("payload="))
        assert payload["user_ids"] == [42] and unquote(payload["text"]) == "仅正文"

    managed_receipts = scoped.collect_delivery_results()
    with observe_notification_progress(lambda _results: None, reserve=lambda _part, _submit: None):
        module.post_message(scoped)
    assert managed_receipts == receipts and request.post_res.call_args == first_request
    assert request.post_res.call_count == 2






@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, "confirmed"),
        (False, "retryable_failure"),
        (None, "unknown"),
        ({"success": False, "message_id": "old"}, "retryable_failure"),
        ({"message_id": "new"}, "confirmed"),
        ((False, {"ok": True}), "retryable_failure"),
        ({"detail": "accepted?"}, "unknown"),
    ],
)
def test_provider_result_requires_confirmation(raw, expected):
    """
    未知结构保持未确认，显式失败优先于其它返回字段。
    """
    assert delivery_status(raw) == expected








@pytest.mark.parametrize(("module_class", "provider", "channel"), [
    (FeishuModule, "feishu", NotificationChannel.Feishu), (QQBotModule, "qqbot", NotificationChannel.QQ),
])
def test_configured_chat_platform_skips_host_notification_without_target(monkeypatch, module_class, provider, channel):
    """
    飞书和 QQ 宿主通知无受众时，不进入客户端的旧会话回退。
    """
    module = module_class()
    module._channel = channel
    conf = NotificationConf(id="fixture", name="fixture", type=provider, enabled=True, switchs=["订阅"])
    monkeypatch.setattr(module, "get_configs", lambda: {"fixture": conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    client = Mock()
    monkeypatch.setattr(module, "get_instance", Mock(return_value=client))
    message = Message(channel=channel, text="通知", mtype=MessageType.Subscribe)
    results = message.collect_delivery_results()

    module.post_message(message)

    assert [(item.connection_id, item.status, item.code) for item in results] == [
        ("fixture", "skipped", "no_target"),
    ]
    assert client.mock_calls == []




























@pytest.mark.parametrize("platform", [NotificationChannel.Telegram, NotificationChannel.WechatClawBot])
@pytest.mark.parametrize("status", ["confirmed", "retryable_failure", "unknown"])
def test_expired_attachment_keeps_frozen_address_and_original_acceptance_state(monkeypatch, tmp_path, platform, status):
    """
    附件过期后不向其他目标发送。已拒绝的分段永久失败，平台可能已接受的分段保持未知。
    """
    path = tmp_path / "fixture.txt"
    path.write_text("附件正文", encoding="utf-8")
    if platform == NotificationChannel.Telegram:
        api = Mock()
        submit = api.send_document
        submit.side_effect = [{
            "confirmed": {"message_id": 123},
            "retryable_failure": TelegramApiError("sendDocument", "ratelimit", 429),
            "unknown": TelegramNetworkError("sendDocument", "timeout"),
        }[status]]
        monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
        client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", auto_start_polling=False)
        deliver = client.send_tracked_attachment
        target = "chat:42"
    else:
        sender = Mock()
        submit = sender.send_tracked_media
        submit.return_value = (status, None)
        bot = WechatClawBot.__new__(WechatClawBot)
        bot._default_target = "other"
        bot._state = {}
        monkeypatch.setattr(bot, "_build_client", lambda: sender)
        deliver = bot.send_tracked_notification
        target = "42"
    progress = {}

    def send(*, first):
        """
        用持久投递合同再次准备原附件。
        """
        from functools import partial

        message = Message(file_path=str(path), userid="42", private_delivery=True)
        results = message.collect_delivery_results()
        parts = NotificationParts(platform, "channel", "account")
        with _observe_recovery(progress, initial=first):
            accepted = deliver(message, "42", receipt=partial(parts.record, message), part_sender=parts.send,
                               plan=parts.plan)
        assert accepted is (results[0].status == "confirmed")
        return results[0]

    original = send(first=True)
    assert original.status == status
    path.unlink()
    expired = send(first=False)
    assert expired.target_id == original.target_id == target
    assert expired.content_digest == original.content_digest
    if status == "retryable_failure":
        assert (expired.status, expired.code) == ("permanent_failure", "content_changed")
        assert next(iter(progress.values()))["status"] == "permanent_failure"
    else:
        assert expired == original
    submit.assert_called_once()
