"""
平台投递冻结计划、确认进度与断点恢复。
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest

from app.application.messaging.delivery import (
    NotificationParts,
    claim_notification_part,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.modules.discord.discord import Discord
from app.modules.feishu.feishu import Feishu
from app.modules.feishu.openapi import FeishuResponse
from app.schemas.message import Message
from app.schemas.types import NotificationChannel


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



@pytest.mark.parametrize("original", [None, "om-parent"])
def test_feishu_tracked_cards_reuse_platform_dedup_for_retry(monkeypatch, original):
    """
    有限流证明时只重试该卡片，接收标识类型和平台 UUID 都保持稳定。
    """
    client = Feishu()
    client._api_client = Mock()
    submit = client._api_client.reply_message if original else client._api_client.create_message
    submit.side_effect = [
        FeishuResponse(0, "ok", {"message_id": "om-first"}),
        FeishuResponse(99991400, "rate limited"),
        FeishuResponse(0, "ok", {"message_id": "om-second"}),
    ]
    monkeypatch.setattr(client, "_build_notification_cards", lambda *_: [{"card": 1}, {"card": 2}])
    parts = NotificationParts(NotificationChannel.Feishu, "app", "tenant")
    progress = {}
    first = True

    def reserve(candidate, should_submit):
        """
        按真实恢复规则保留确认，限流的卡片可再次提交。
        """
        nonlocal progress
        existing, progress = claim_notification_part(
            progress, candidate, initial_attempt=first, should_submit=should_submit,
        )
        return existing

    def plan(deliveries):
        """
        首次派发保存卡片清单。
        """
        nonlocal progress
        if first:
            progress = freeze_notification_parts(progress, deliveries)

    def record(deliveries):
        """
        保存平台确认结果。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, deliveries)

    receipt = Mock()
    message = Message(title="卡片", original_message_id=original)
    target = ("same-user", None, "user_id")
    with observe_notification_progress(record, reserve=reserve, plan=plan):
        assert not client.send_tracked_notification(
            message, target, nonce="fixture-event", receipt=receipt, plan=parts.plan, part_sender=parts.send,
        )
        first = False
        assert client.send_tracked_notification(
            message, target, nonce="fixture-event", receipt=receipt, plan=parts.plan, part_sender=parts.send,
        )
    requests = [call.kwargs for call in submit.call_args_list]
    assert len(requests) == 3 and requests[1] == requests[2]
    assert requests[0]["uuid"] != requests[1]["uuid"]
    if original:
        assert all(request["message_id"] == original for request in requests)
        client._api_client.create_message.assert_not_called()
    else:
        assert all(request["receive_id_type"] == "user_id" for request in requests)
        client._api_client.reply_message.assert_not_called()
    assert {part["message_id"] for part in progress.values()} == {"om-first", "om-second"}



def test_feishu_native_image_does_not_retry_replaced_source(monkeypatch, tmp_path):
    """
    限流后同路径的图像字节改变时拒绝续发，已确认的说明也不会再次发送。
    """
    from app.adapters.system import attachment

    client = Feishu()
    client._api_client = Mock()
    client._api_client.create_message.side_effect = [
        FeishuResponse(0, "ok", {"message_id": "caption"}), FeishuResponse(99991400, "limited"),
    ]
    source = tmp_path / "image.png"
    content = b"\x89PNG\r\n\x1a\noriginal"
    source.write_bytes(content)
    monkeypatch.setattr(attachment, "get_runtime_setting", lambda _: tmp_path)
    uploaded = []

    def upload(path):
        """
        记录实际上传的字节。
        """
        uploaded.append(path.read_bytes())
        return "key"

    monkeypatch.setattr(client, "_upload_image", upload)
    parts = NotificationParts(NotificationChannel.Feishu, "feishu", "binding")
    receipt = Mock()
    progress = {}
    message = Message(title="说明", native_image=True, image=str(source))
    for initial in (True, False):
        with _observe_recovery(progress, initial=initial):
            assert not client.send_tracked_notification(
                message, ("member", None, "user_id"), nonce="fixture",
                receipt=receipt, plan=parts.plan, part_sender=parts.send,
            )
        source.write_bytes(b"\x89PNG\r\n\x1a\nchanged")
    assert uploaded == [content]
    assert client._api_client.create_message.call_count == 2
    assert receipt.call_args.args[-2:] == ("permanent_failure", "content_changed")



@pytest.mark.parametrize("case", ["image", "file", "missing", "upload-failed"])
def test_feishu_tracked_attachment_keeps_recipient_and_caption(tmp_path, monkeypatch, case):
    """
    图片保留卡片正文，文件单独发送正文，附件失败时保持原接收者并报告原因。
    """
    client = Feishu()
    client._api_client = Mock()
    submit = client._api_client.create_message
    submit.return_value = FeishuResponse(0, "ok", {"message_id": "om-ok"})
    source = tmp_path / ("fixture.png" if case == "image" else "fixture.srt")
    if case != "missing":
        source.write_bytes(b"fixture")
    monkeypatch.setattr(client, "_upload_image", Mock(return_value="image-key"))
    monkeypatch.setattr(client, "_upload_file", Mock(return_value=None if case == "upload-failed" else "file-key"))
    parts = NotificationParts(NotificationChannel.Feishu, "app", "tenant")
    receipt = Mock()
    result = client.send_tracked_notification(
        Message(file_path=str(source), title="附件", text="说明"),
        ("fixture-user", None, "user_id"), nonce="file-event",
        receipt=receipt, plan=parts.plan, part_sender=parts.send,
    )
    expected = {
        "image": ["interactive"], "file": ["file", "text"], "missing": [], "upload-failed": [],
    }
    requests = [call.kwargs for call in submit.call_args_list]
    assert [request["msg_type"] for request in requests] == expected[case]
    assert all(request["receive_id"] == "fixture-user" for request in requests)
    assert result is bool(expected[case])
    if result:
        assert "说明" in requests[-1]["content"]
    else:
        error = ("permanent_failure", "attachment_unavailable") if case == "missing" else (
            "retryable_failure", "attachment_upload_failed",
        )
        assert receipt.call_args_list[0].args == ("user_id:fixture-user", 0, *error)



def test_discord_tracked_edit_keeps_thread_and_retries_only_rate_limited_part(monkeypatch):
    """
    编辑和续发固定在原线程，明确限流后的重试跳过已确认的编辑。
    """
    client = Discord.__new__(Discord)
    client._loop = Mock()
    client._channel_id = 99
    client.get_state = Mock(return_value=True)
    channel = Mock(spec=discord.abc.Messageable)
    channel.id = 12
    platform_response = SimpleNamespace(status=429, reason="Too Many Requests")
    original = Mock()
    original.edit = AsyncMock(return_value=SimpleNamespace(id=34))
    channel.fetch_message = AsyncMock(return_value=original)
    channel.send = AsyncMock(side_effect=[discord.HTTPException(platform_response, "rate limit"), SimpleNamespace(id=56)])
    client._resolve_channel = AsyncMock(return_value=channel)
    message = Message(original_chat_id="12", original_message_id=34)
    monkeypatch.setattr(Message, "channel_text_chunks", Mock(return_value=["首段", "续段"]))
    parts = NotificationParts(NotificationChannel.Discord, "app", "account")
    progress = {}
    receipt = Mock()

    def submit(coroutine, _loop):
        """
        执行真实发送协程并保留结果或异常，隔离 Discord 线程和网络。
        """
        future = Mock()
        try:
            future.result.return_value = asyncio.run(coroutine)
        except discord.HTTPException as error:
            future.result.side_effect = error
        return future

    monkeypatch.setattr("app.modules.discord.discord.asyncio.run_coroutine_threadsafe", submit)
    with _observe_recovery(progress, initial=True):
        assert not client.send_tracked_notification(
            message, None, event="fixture-event", receipt=receipt, plan=parts.plan, part_sender=parts.send,
        )
    with _observe_recovery(progress, initial=False):
        assert client.send_tracked_notification(
            message, None, event="fixture-event", receipt=receipt, plan=parts.plan, part_sender=parts.send,
        )
    original.edit.assert_awaited_once()
    channel.fetch_message.assert_awaited_once_with(34)
    assert client._resolve_channel.await_args.args == (None, "12")
    assert channel.send.await_count == 2
    assert channel.send.await_args_list[0].kwargs["nonce"] == channel.send.await_args_list[1].kwargs["nonce"]
    assert {part["message_id"] for part in progress.values()} == {"34", "56"}
