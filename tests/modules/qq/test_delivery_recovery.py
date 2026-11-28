"""
平台投递冻结计划、确认进度与断点恢复。
"""



from contextlib import nullcontext
from unittest.mock import Mock

import pytest

from app.application.messaging.delivery import (
    claim_notification_part,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.modules.qqbot.module import QQBotModule
from app.modules.qqbot.qqbot import QQBot
from app.schemas.message import Message
from app.schemas.system import NotificationConf
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



@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("scenario", ["rate_limited", "timeout", "first_timeout", "markdown_denied"])
def test_qq_recovers_known_parts_and_only_falls_back_on_explicit_rejection(monkeypatch, scenario, managed):
    """
    QQ 恢复保留群地址和已确认分段，遇到超时不重复发送。
    """
    client = QQBot.__new__(QQBot)
    client._ready = True
    client._app_id = "fixture-app"
    client._app_secret = "fixture-secret"
    acknowledged = Mock(status_code=200, **{"json.return_value": {"id": "fixture-message"}})
    limited = Mock(status_code=429, **{"json.return_value": {"code": 1}})
    markdown_denied = Mock(status_code=403, **{"json.return_value": {"code": 11244}})
    replies = {
        "rate_limited": [acknowledged, limited, acknowledged],
        "timeout": [acknowledged, None],
        "first_timeout": [None],
        "markdown_denied": [markdown_denied, acknowledged],
    }
    post = Mock(side_effect=replies[scenario])
    monkeypatch.setattr("app.modules.qqbot.api.RequestUtils", Mock(**{"return_value.post_res": post}))
    monkeypatch.setattr("app.modules.qqbot.qqbot.get_access_token", lambda *_: "fixture-token")
    config = NotificationConf(id="qq", name="qq", type="qqbot", enabled=True, identity_namespace="binding")
    module = QQBotModule()
    module._channel = NotificationChannel.QQ
    monkeypatch.setattr(module, "get_configs", lambda: {"qq": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    monkeypatch.setattr(Message, "channel_text_chunks", lambda *_: ["第一段", "第二段"])
    progress = {}
    initial = True

    def observe(results):
        """
        保存当前认领取得的各分段结果。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, results)

    def reserve(part, should_submit):
        """
        使用真实认领规则限制重复提交。
        """
        nonlocal progress
        result, progress = claim_notification_part(
            progress, part, initial_attempt=initial, should_submit=should_submit,
        )
        return result

    def plan(parts):
        """
        冻结首次解析出的群地址和分段。
        """
        nonlocal progress
        if initial:
            progress = freeze_notification_parts(progress, parts)

    def deliver(recipient):
        """
        从通知模块入口运行一次派发。
        """
        message = Message(channel=NotificationChannel.QQ, userid=recipient, text="完整正文")
        results = message.collect_delivery_results()
        with observe_notification_progress(observe, reserve=reserve, plan=plan) if managed else nullcontext():
            module.post_message(message)
        assert all(item.content_digest for item in results)
        if results[0].status == "confirmed":
            assert results[0].message_id == "fixture-message"
        return [item.status for item in results]

    initial_status = {
        "rate_limited": ["confirmed", "retryable_failure"],
        "timeout": ["confirmed", "unknown"],
        "first_timeout": ["unknown", "retryable_failure"],
        "markdown_denied": ["confirmed", "confirmed"],
    }[scenario]
    assert deliver("group:room") == initial_status
    if managed:
        initial = False
        assert deliver("group:room") == (["confirmed", "confirmed"] if scenario == "rate_limited" else initial_status)
        assert deliver("room") == ["permanent_failure", "permanent_failure"]
    assert all(call.args[0].endswith("/groups/room/messages") for call in post.call_args_list)
    payloads = [call.kwargs["json"] for call in post.call_args_list]
    if scenario == "markdown_denied":
        assert payloads == [{"markdown": {"content": "第一段"}, "msg_type": 2},
                            {"content": "完整正文", "msg_type": 0}]
    else:
        expected = {
            "rate_limited": ["第一段", "第二段", "第二段"] if managed else ["第一段", "第二段"],
            "timeout": ["第一段", "第二段"],
            "first_timeout": ["第一段"],
        }
        assert [item["markdown"]["content"] for item in payloads] == expected[scenario]
