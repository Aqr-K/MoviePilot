"""
平台投递冻结计划、确认进度与断点恢复。
"""





from unittest.mock import Mock

import pytest

from app.application.messaging.delivery import (
    NotificationParts,
    claim_notification_part,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
    uses_legacy_attachment_layout,
)
from app.modules.telegram.botapi import TelegramApiError, TelegramNetworkError
from app.modules.telegram.module import TelegramModule
from app.modules.telegram.telegram import Telegram
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType, NotificationChannel


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



@pytest.mark.parametrize("long_caption", [False, True])
def test_telegram_combined_image_and_file_retry_preserves_original_topic(monkeypatch, tmp_path, long_caption):
    """
    同一业务通知的原图和文件拥有不同分段，限流恢复只再次上传文件。
    """
    api = Mock()
    api.send_photo.return_value = {"message_id": 100}
    api.send_message.return_value = {"message_id": 103}
    detail = "文" * 1300 if long_caption else None
    api.send_document.side_effect = [TelegramApiError("sendDocument", "limited", error_code=429), {"message_id": 101}]
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", auto_start_polling=False)
    monkeypatch.setattr(client, "_is_chat_rate_limited", lambda *_a, **_kw: False)
    config = NotificationConf(id="telegram", name="telegram", type="telegram", enabled=True, identity_namespace="binding")
    module = TelegramModule()
    module._channel = NotificationChannel.Telegram
    monkeypatch.setattr(module, "get_configs", lambda: {"telegram": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    path = tmp_path / "report.txt"
    path.write_text("file content")
    image = tmp_path / "original.png"
    content = b"\x89PNG\r\n\x1a\noriginal"
    image.write_bytes(content)
    snapshot = {}
    first = True

    def plan(parts):
        """
        首次保存两组不同分段。
        """
        nonlocal snapshot
        if first:
            snapshot = freeze_notification_parts(snapshot, parts)

    def record(results):
        """
        记录已经获得的真实确认结果。
        """
        nonlocal snapshot
        snapshot = merge_notification_progress(snapshot, results)

    def reserve(part, should_submit):
        """
        恢复沿用同一目标的已保存发送记录。
        """
        nonlocal snapshot
        result, snapshot = claim_notification_part(snapshot, part, initial_attempt=first, should_submit=should_submit)
        return result

    def run():
        """
        由真实的模块拆分并发给同一话题。
        """
        message = Message(
            channel=NotificationChannel.Telegram, source="telegram", userid="123", original_chat_id="-789", thread_id="17",
            title="说明", text=detail, native_image=True, image=str(image), file_path=str(path), parse_mode="plain",
        )
        results = message.collect_delivery_results()
        with observe_notification_progress(record, reserve=reserve, plan=plan):
            module.post_message(message)
        expected_parts = [0, 1, 4096] if long_caption else [0, 4096]
        assert [item.part for item in results] == expected_parts
        assert {item.target_id for item in results} == {"chat:-789:topic:17"}
        return [item.status for item in results]

    confirmed = ["confirmed"] * (2 if long_caption else 1)
    assert run() == [*confirmed, "retryable_failure"]
    first = False
    assert run() == [*confirmed, "confirmed"]
    api.send_photo.assert_called_once()
    assert api.send_photo.call_args.kwargs["photo"] == content
    assert api.send_photo.call_args.kwargs["caption"] == (None if long_caption else "说明")
    if long_caption:
        api.send_message.assert_called_once()
        assert api.send_message.call_args.kwargs["text"] == f"说明\n{detail}"
    else:
        api.send_message.assert_not_called()
    assert api.send_document.call_count == 2
    assert all(call.kwargs["chat_id"] == "-789" and call.kwargs["message_thread_id"] == 17
               and not call.kwargs["caption"] for call in api.send_document.call_args_list)
    assert path.read_text() == "file content"



def test_telegram_resumes_frozen_legacy_file_without_new_image_part(monkeypatch, tmp_path):
    """
    旧组合消息只冻结了文件时，升级后按原受众、编号和摘要恢复该分段。
    """
    api = Mock()
    api.send_document.side_effect = [TelegramApiError("sendDocument", "limited", error_code=429), {"message_id": 102}]
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", auto_start_polling=False)
    monkeypatch.setattr(client, "_is_chat_rate_limited", lambda *_a, **_kw: False)
    config = NotificationConf(id="telegram", name="telegram", type="telegram", enabled=True, identity_namespace="binding")
    module = TelegramModule()
    module._channel = NotificationChannel.Telegram
    monkeypatch.setattr(module, "get_configs", lambda: {"telegram": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    path = tmp_path / "report.txt"
    path.write_text("file content")
    snapshot = {}
    first = True

    def reserve(part, should_submit):
        """
        按原认领与分段记录校验提交。
        """
        nonlocal snapshot
        result, snapshot = claim_notification_part(snapshot, part, initial_attempt=first, should_submit=should_submit)
        return result

    def record(results):
        """
        存下原接口的结果供升级后恢复。
        """
        nonlocal snapshot
        snapshot = merge_notification_progress(snapshot, results)

    message = Message(
        channel=NotificationChannel.Telegram, source="telegram", userid="123", title="说明",
        image="https://fixture.example/cover.png", file_path=str(path), parse_mode="plain",
    )
    old_parts = NotificationParts(NotificationChannel.Telegram, config.id, config.identity_namespace)
    with observe_notification_progress(record, reserve=reserve):
        assert not client.send_tracked_attachment(
            message, "123", receipt=lambda *_: None, part_sender=old_parts.send, plan=old_parts.plan,
        )
    assert uses_legacy_attachment_layout(snapshot)
    first = False
    results = message.collect_delivery_results()
    with observe_notification_progress(record, reserve=reserve, legacy_attachment_layout=True):
        module.post_message(message)
    assert [(result.part, result.status) for result in results] == [(0, "confirmed")]
    assert api.send_document.call_count == 2
    api.send_photo.assert_not_called()



def test_telegram_managed_text_does_not_repeat_confirmed_or_unknown_parts(monkeypatch):
    """
    Telegram 普通文本恢复时保留话题和确认状态，未知提交仅发送一次。
    """
    api = Mock()
    api.send_message.side_effect = [
        {"message_id": 123}, TelegramNetworkError("sendMessage", "timeout"),
    ]
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", TELEGRAM_TOPIC_ID="7", auto_start_polling=False)
    config = NotificationConf(id="telegram", name="telegram", type="telegram", enabled=True, identity_namespace="binding")
    module = TelegramModule()
    module._channel = NotificationChannel.Telegram
    monkeypatch.setattr(module, "get_configs", lambda: {"telegram": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    snapshot = {}
    first = True

    def plan(parts):
        """
        首次调用时保存连接内的完整发送清单。
        """
        nonlocal snapshot
        if first:
            snapshot = freeze_notification_parts(snapshot, parts)

    def record(results):
        """
        保存当前认领获得的新发送状态。
        """
        nonlocal snapshot
        snapshot = merge_notification_progress(snapshot, results)

    def reserve(part, should_submit):
        """
        根据当前认领和保存的地址决定是否可以发送。
        """
        nonlocal snapshot
        result, snapshot = claim_notification_part(snapshot, part, initial_attempt=first, should_submit=should_submit)
        return result

    def run():
        """
        从通知模块发送需要两段的纯文本。
        """
        message = Message(
            channel=NotificationChannel.Telegram, mtype=MessageType.Subscribe, parse_mode="plain", text="文" * 4200,
        )
        results = message.collect_delivery_results()
        with observe_notification_progress(record, reserve=reserve, plan=plan):
            module.post_message(message)
        return [(item.target_id, item.status) for item in results]

    monkeypatch.setattr(config, "switchs", [MessageType.Subscribe.value])
    expected = [("chat:-100:topic:7", "confirmed"), ("chat:-100:topic:7", "unknown")]
    assert run() == expected
    first = False
    assert run() == expected
    assert api.send_message.call_count == 2
    assert {item["message_id"] for item in snapshot.values() if item["status"] == "confirmed"} == {"123"}
    assert all(call.kwargs["chat_id"] == "-100" and call.kwargs["message_thread_id"] == 7
               for call in api.send_message.call_args_list)



@pytest.mark.parametrize("received_reply", [True, False])
@pytest.mark.parametrize("force_reply", [True, False])
def test_telegram_rich_fallback_requires_confirmed_rejection(monkeypatch, received_reply, force_reply):
    """
    富文本降级只发生在平台明确拒绝后，并保留原话题。
    """
    api = Mock()
    api.send_rich_message.side_effect = (
        TelegramApiError("sendRichMessage", "method unavailable", 404)
        if received_reply else TelegramNetworkError("sendRichMessage", "timeout")
    )
    api.send_message.return_value = {"message_id": 31}
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", TELEGRAM_TOPIC_ID="7", auto_start_polling=False)
    planned = Mock()
    delivered = Mock()

    def submit(_target, _part, _content, _should_submit, send):
        """
        在独立平台测试中立即调用已组装的计划提交操作。
        """
        result = send()
        return result[0], result[1]

    message = Message(text="标题", force_reply=force_reply, original_chat_id="-100" if force_reply else None,
                      original_message_id=81 if force_reply else None, thread_id="7" if force_reply else None)
    assert client.send_tracked_message(
        message, None, rich_message="**标题**", receipt=delivered, part_sender=submit, plan=planned,
    ) is received_reply
    api.send_rich_message.assert_called_once()
    if force_reply:
        assert api.send_rich_message.call_args.kwargs["reply_parameters"] == {"message_id": 81}
        assert api.send_rich_message.call_args.kwargs["reply_markup"]["force_reply"]
    if received_reply:
        context = {"reply_markup": api.send_rich_message.call_args.kwargs["reply_markup"], "reply_to_message_id": 81} if force_reply else {}
        api.send_message.assert_called_once_with(
            chat_id="-100", text="**标题**", parse_mode="", message_thread_id=7, **context,
        )
        delivered.assert_called_once_with("chat:-100:topic:7", 0, "confirmed", None)
    else:
        api.send_message.assert_not_called()
        delivered.assert_called_once_with("chat:-100:topic:7", 0, "unknown", "response_unconfirmed")



def test_telegram_managed_edit_preserves_original_message_after_restart(monkeypatch):
    """
    确认原群消息已经编辑，恢复时跳过确认，旧连接或新目标不能替代原消息。
    """
    api = Mock()
    api.edit_message_text.side_effect = TelegramApiError("editMessageText", "message is not modified", 400)
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", auto_start_polling=False)
    config = NotificationConf(id="telegram", name="telegram", type="telegram", enabled=True, identity_namespace="binding")
    module = TelegramModule()
    module._channel = NotificationChannel.Telegram
    monkeypatch.setattr(module, "get_configs", lambda: {"telegram": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    message = Message(
        channel=NotificationChannel.Telegram, userid="111", original_chat_id="-200", original_message_id=41,
        thread_id="7", text="选项", parse_mode="plain", buttons=[[{"text": "确认", "callback_data": "fixture"}]],
    )
    results = message.collect_delivery_results()
    progress = {}
    for initial in (True, False):
        results.clear()
        with _observe_recovery(progress, initial=initial):
            module.post_message(message)
        assert [(item.target_id, item.status) for item in results] == [("chat:-200:topic:7", "confirmed")]
    api.edit_message_text.assert_called_once()
    assert api.edit_message_text.call_args.kwargs["message_id"] == 41
    assert api.edit_message_text.call_args.kwargs["chat_id"] == "-200"
    assert api.edit_message_text.call_args.kwargs["reply_markup"]["inline_keyboard"]
    api.send_message.assert_not_called()



def test_telegram_tracked_voice_preserves_source_after_unknown_result(monkeypatch, tmp_path):
    """
    语音读取后提交一次，超时状态和源文件都可供后台恢复核对。
    """
    audio = tmp_path / "voice.ogg"
    audio.write_bytes(b"fixture-audio")
    api = Mock()
    api.send_voice.side_effect = TelegramNetworkError("sendVoice", "timeout")
    monkeypatch.setattr("app.modules.telegram.telegram.TelegramBotApi", Mock(return_value=api))
    client = Telegram(TELEGRAM_TOKEN="fixture", TELEGRAM_CHAT_ID="-100", auto_start_polling=False)
    receipt = Mock()
    plan = Mock()

    def submit(_target, _part, _content, _should_submit, send):
        """
        调用真实附件发送并返回平台分类。
        """
        result = send()
        return result[0], result[1]

    assert not client.send_tracked_attachment(
        Message(voice_path=str(audio)), "42", receipt=receipt, part_sender=submit, plan=plan,
    )
    assert audio.read_bytes() == b"fixture-audio"
    api.send_voice.assert_called_once()
    assert api.send_voice.call_args.kwargs["chat_id"] == "42"
    receipt.assert_called_once_with("chat:42", 0, "unknown", "response_unconfirmed")
