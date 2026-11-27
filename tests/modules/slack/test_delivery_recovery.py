"""
平台投递冻结计划、确认进度与断点恢复。
"""





from unittest.mock import Mock

import pytest
from slack_sdk.errors import SlackApiError

from app.application.messaging.delivery import (
    NotificationParts,
    claim_notification_part,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.modules.slack.slack import Slack
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



@pytest.mark.parametrize("original", [None, "2.3"])
def test_slack_tracked_batches_restore_thread_and_disable_sdk_retries(monkeypatch, original):
    """
    仅通知模式无需 Socket Mode，新认领只补发 Slack 明确限流的批次。
    """
    client_factory = Mock()
    socket_factory = Mock()
    monkeypatch.setattr("app.modules.slack.slack.WebClient", client_factory)
    monkeypatch.setattr("app.modules.slack.slack.SocketModeHandler", socket_factory)
    slack = Slack(SLACK_OAUTH_TOKEN="fixture", start_socket=False)
    client_factory.assert_called_once_with(token="fixture", retry_handlers=[])
    socket_factory.assert_not_called()
    api = client_factory.return_value
    first_response = {"ok": True, "ts": "1.2"}
    retries = [SlackApiError("rate limit", Mock(status_code=429)), {"ok": True, "ts": "3.4"}]
    api.chat_update.return_value = first_response
    api.chat_postMessage.side_effect = retries if original else [first_response, *retries]
    parts = NotificationParts(NotificationChannel.Slack, "app", "workspace")
    progress = {}
    initial = True

    def plan(deliveries):
        """
        保存首次派发已确定的全部批次。
        """
        nonlocal progress
        if initial:
            progress = freeze_notification_parts(progress, deliveries)

    def record(deliveries):
        """
        保存具体批次的确认记录。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, deliveries)

    def reserve(part, should_submit):
        """
        使用已有确认决定当前批次是否应发送。
        """
        nonlocal progress
        recorded, progress = claim_notification_part(
            progress, part, initial_attempt=initial, should_submit=should_submit,
        )
        return recorded

    message = Message(text="文" * 4200, original_chat_id="C1", thread_id="10.20", original_message_id=original)
    receipt = Mock()
    with observe_notification_progress(record, reserve=reserve, plan=plan):
        assert not slack.send_tracked_message(message, None, receipt=receipt, part_sender=parts.send, plan=parts.plan)
        initial = False
        assert slack.send_tracked_message(message, None, receipt=receipt, part_sender=parts.send, plan=parts.plan)
    calls = [call.kwargs for call in api.chat_postMessage.call_args_list]
    if original:
        assert api.chat_update.call_count == 1
        edit = api.chat_update.call_args.kwargs
        assert edit["channel"] == "C1" and edit["ts"] == original
        assert len(calls) == 2
    else:
        api.chat_update.assert_not_called()
        assert len(calls) == 3
    assert calls[-2] == calls[-1]
    assert all(call["channel"] == "C1" and call["thread_ts"] == "10.20" for call in calls)
    assert {part["message_id"] for part in progress.values()} == {"1.2", "3.4"}
