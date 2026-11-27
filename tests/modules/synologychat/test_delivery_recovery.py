"""
平台投递冻结计划、确认进度与断点恢复。
"""


import json
from contextlib import nullcontext
from unittest.mock import Mock

import pytest

from app.application.messaging.delivery import (
    claim_notification_part,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.modules.apppush import AppPushModule
from app.modules.synologychat import SynologyChatModule
from app.modules.synologychat.synologychat import SynologyChat
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



def test_apppush_partial_relay_report_is_not_replayed(monkeypatch):
    """
    中转仅确认部分设备时保留未知，恢复不再次提交该账号或新增账号。
    """
    module = AppPushModule()
    module._channel = NotificationChannel.AppPush
    conf = NotificationConf(id="app", name="app", type="apppush", enabled=True, identity_namespace="binding")
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    partial_delivery = {"total": 2, "accepted": 1, "failed": ["device"]}
    complete_delivery = {"total": 1, "accepted": 1}
    request = Mock(side_effect=[partial_delivery, complete_delivery, partial_delivery, complete_delivery])
    monkeypatch.setattr(module, "_request", request)
    progress = {}

    def dispatch(owners, *, initial=None):
        """
        从通知提供方入口发送显式选中的账号。
        """
        msg = Message(channel=NotificationChannel.AppPush, title="完成", targets={"apppush": owners})
        msg.set_notification_route_scope("all")
        receipts = msg.collect_delivery_results()
        with nullcontext() if initial is None else _observe_recovery(progress, initial=initial):
            module.post_message(msg)
        return [(receipt.target_id, receipt.status, receipt.code) for receipt in receipts]

    planned = [("alice", "unknown", "relay_devices_unconfirmed"), ("bob", "confirmed", None)]
    assert dispatch(("alice", "bob")) == planned
    assert dispatch(("alice", "bob"), initial=True) == planned
    assert dispatch(("alice", "bob", "carol"), initial=False) == [
        *planned, ("carol", "permanent_failure", "unplanned_target"),
    ]
    assert [call.args[3]["owner"] for call in request.call_args_list] == ["alice", "bob", "alice", "bob"]



@pytest.mark.parametrize("http_status,expected", [
    (200, ("confirmed", None, None)),
    (401, ("permanent_failure", "relay_rejected", None)),
    (429, ("retryable_failure", "rate_limited", 17)),
    (503, ("unknown", "relay_unconfirmed", None)),
    (None, ("unknown", "relay_unconfirmed", None)),
])
def test_apppush_normal_delivery_preserves_relay_http_result(monkeypatch, http_status, expected):
    """
    实际中转适配器保留 HTTP 拒绝和限流状态，不把超时视为已投递或可盲重试。
    """
    conf = NotificationConf(id="app", name="app", type="apppush", enabled=True, config={
        "PUSH_SERVER_URL": "https://fixture.example/", "PUSH_RELAY_KEY": "synthetic" * 4,
    })
    response = Mock(status_code=http_status, headers={"Retry-After": "17"})
    response.json.return_value = {"total": 1, "accepted": 1, "failed": []}
    request = Mock(return_value=response if http_status is not None else None)
    monkeypatch.setattr("app.adapters.external.server.RequestUtils", Mock(**{"return_value.request": request}))
    module = AppPushModule()
    module._channel = NotificationChannel.AppPush
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    message = Message(channel=NotificationChannel.AppPush, source=conf.name, text="仅正文", targets={"apppush": "alice"})
    message.set_notification_route_scope("user")
    receipts = message.collect_delivery_results()
    module.post_message(message)

    receipt, = receipts
    assert (receipt.status, receipt.code, receipt.retry_after) == expected
    assert request.call_args.kwargs["json"]["body"] == "仅正文"
    assert request.call_args.kwargs["json"]["owner"] == receipt.target_id == "alice"



def test_synologychat_reports_individual_failures_for_explicit_broadcast(monkeypatch):
    """
    群晖广播逐人投递，业务拒绝独立于同批其他用户的成功回执。
    """
    client = SynologyChat(SYNOLOGYCHAT_WEBHOOK="https://fixture.example/chat", SYNOLOGYCHAT_TOKEN="synthetic")
    users = Mock(status_code=200)
    users.json.return_value = {"data": {"users": [
        {"user_id": 42, "deleted": False}, {"user_id": 43, "deleted": False}, {"user_id": 44, "deleted": True},
    ]}}
    accepted = Mock(status_code=200, **{"json.return_value": {"success": True}})
    rejected = Mock(status_code=200, **{"json.return_value": {"error": {"code": 119}}})
    transport = Mock(**{"get_res.return_value": users, "post_res.side_effect": [accepted, rejected]})
    monkeypatch.setattr(client, "_req", transport)
    module = SynologyChatModule()
    module._channel = NotificationChannel.SynologyChat
    conf = NotificationConf(id="chat", name="chat", type="synologychat", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    message = Message(channel=NotificationChannel.SynologyChat, source=conf.name, text="仅正文")
    message.set_notification_route_scope("all")
    receipts = message.collect_delivery_results()
    module.post_message(message)

    assert [(result.target_id, result.status) for result in receipts] == [
        ("user:42", "confirmed"), ("user:43", "permanent_failure"),
    ]
    assert [json.loads(call.kwargs["data"].removeprefix("payload="))["user_ids"]
            for call in transport.post_res.call_args_list] == [[42], [43]]
