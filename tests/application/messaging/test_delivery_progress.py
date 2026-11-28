"""
冻结投递计划在重启、身份变更、时间窗及未知确认下的恢复约束。
"""

from datetime import datetime
from unittest.mock import Mock

import pytest

from app.application.messaging import delivery
from app.schemas.channel import NotificationRule, NotificationSendTime
from app.schemas.delivery import DeliveryResult
from app.schemas.message import Message, MessageResponse
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType, NotificationChannel


def _part(**updates):
    """
    构造独立传输标识上的完整分段，不借用内置平台身份。
    """
    return DeliveryResult(
        channel=NotificationChannel("platform:example.test"), connection_id="connection-a",
        identity_namespace="namespace-a", target_id="opaque:recipient", content_digest="digest-a",
        part=0, status="retryable_failure",
    ).model_copy(update=updates)


def test_restart_freezes_rules_connections_and_confirmed_progress():
    """
    配置修改不能扩张已冻结计划，恢复仅补发明确失败且内容未变的分段。
    """
    rule = NotificationRule(name="最初规则", message_types=(MessageType.Subscribe.value,), kind="bound")
    configs = {"connection-a": (rule,)}
    bindings, snapshot = delivery.read_or_freeze_notification_connections({}, frozenset({("connection-a", "namespace-a")}))
    frozen_rules, snapshot = delivery.read_or_freeze_notification_rules(snapshot, configs)
    snapshot = delivery.seal_notification_plan(snapshot, (_part(), _part(part=1), _part(part=2)))
    snapshot = delivery.merge_notification_progress(snapshot, (_part(status="confirmed"), _part(part=1, status="unknown")))
    assert not delivery.notification_plan_incomplete(snapshot)
    assert not delivery.uses_legacy_attachment_layout(snapshot)
    assert delivery.read_or_freeze_notification_connections(snapshot, frozenset({("replacement", "other")}))[0] == bindings
    assert delivery.read_or_freeze_notification_rules(snapshot, {"replacement": ()})[0] == frozen_rules
    assert delivery.pending_notification_parts(snapshot) == frozenset({delivery.notification_part_key(_part(part=1)), delivery.notification_part_key(_part(part=2))})
    for status, index in (("confirmed", 0), ("unknown", 1)):
        result, unchanged = delivery.claim_notification_part(snapshot, _part(part=index), initial_attempt=False, should_submit=True)
        assert result.status == status
        assert unchanged == snapshot
    retry, snapshot = delivery.claim_notification_part(snapshot, _part(part=2), initial_attempt=False, should_submit=True)
    assert retry is None
    assert snapshot[delivery.notification_part_key(_part(part=2))]["status"] == "unknown"
    with pytest.raises(ValueError, match="无法再次冻结"):
        delivery.seal_notification_plan(snapshot, ())
    conf = NotificationConf(id="connection-a", name="test", type="telegram")
    assert delivery.notification_rules_for_dispatch(conf) is None
    assert not delivery.notification_rules_are_frozen()
    with delivery.observe_notification_progress(lambda _results: None, rules=frozen_rules, legacy_attachment_layout=True):
        assert delivery.notification_rules_are_frozen()
        assert delivery.notification_rules_for_dispatch(conf) == (rule,)
        assert delivery.legacy_attachment_layout_active()
    assert not delivery.notification_rules_are_frozen()
    assert not delivery.legacy_attachment_layout_active()


@pytest.mark.parametrize("change,expected", [
    ({"identity_namespace": None}, "unverified_identity"),
    ({"identity_namespace": "other"}, "unplanned_target"),
    ({"connection_id": "other"}, "unplanned_target"),
    ({"target_id": "other"}, "unplanned_target"),
    ({"part": 1}, "unplanned_target"),
    ({"content_digest": "changed"}, "content_changed"),
])
def test_recovery_rejects_changed_identity_target_or_content(change, expected):
    """
    旧计划拒绝新身份、目标与内容；拒绝记录不得污染原始确认进度。
    """
    snapshot = delivery.seal_notification_plan({}, (_part(),))
    result, changed = delivery.claim_notification_part(snapshot, _part(**change), initial_attempt=False, should_submit=True, planned_only=True)
    assert result.code == expected and result.status == "permanent_failure"
    merged = delivery.merge_notification_progress(snapshot, (result,))
    assert merged == snapshot
    if expected == "content_changed":
        assert changed[delivery.notification_part_key(_part())]["code"] == expected
    else:
        assert changed == snapshot


def test_preflight_and_real_submit_preserve_message_id_and_rate_limit():
    """
    准备阶段无网络副作用，实际提交传播完整回执并在退出后恢复上下文。
    """
    plans, progress = [], []
    submit = Mock(return_value=("retryable_failure", "rate_limited", "message-1", 45))
    parts = delivery.NotificationParts(_part().channel, "connection-a", "namespace-a", part_offset=2)
    with delivery.observe_notification_progress(progress.extend, reserve=lambda *_args: None, freeze=plans.append):
        assert delivery.managed_notification_dispatch() and delivery.notification_preflight_required()
        with delivery.collect_notification_preflight():
            assert delivery.notification_preflight_active()
            parts.plan((("opaque:recipient", 0, "正文"),))
            result = parts.send_result("opaque:recipient", 0, "正文", True, submit)
            assert result.status == "confirmed"
        submit.assert_not_called()
        assert len(plans[0]) == 1 and plans[0][0].part == 2
        status, code = parts.send("opaque:recipient", 0, "正文", True, submit)
        assert (status, code) == ("retryable_failure", "rate_limited")
        message = Message(text="正文")
        receipt = message.collect_delivery_results()
        parts.record(message, "opaque:recipient", 0, status, code)
        assert receipt[0].message_id == "message-1" and receipt[0].retry_after == 45
        assert progress == receipt
        parts.record(message, None, 1, "skipped", "no_target")
        assert receipt[-1].part == 3 and receipt[-1].target_id is None
        assert parts.send_result("opaque:recipient", 1, "正文", False, submit).code == "previous_part_unconfirmed"
    assert not delivery.managed_notification_dispatch()
    assert not delivery.notification_preflight_active()
    assert not delivery.notification_preflight_required()
    assert len(submit.call_args_list) == 1
    with delivery.observe_notification_progress(progress.extend, plan=plans.append):
        parts.plan((("opaque:recipient", 3, "另段"),))
    assert plans[-1][0].part == 5


def test_time_window_skips_before_submit_and_legacy_claim_is_at_most_once(monkeypatch):
    """
    恢复时已错过窗口直接终止该分段；不重复调用未知确认的历史插件。
    """
    rule = NotificationRule(message_types=(MessageType.Subscribe.value,), kind="bound", send_time=NotificationSendTime(start="08:00", end="09:00"))
    assert delivery.notification_rule_time_allows(rule, datetime(2026, 1, 1, 8, 30))
    assert not delivery.notification_rule_time_allows(rule, datetime(2026, 1, 1, 10, 0))
    monkeypatch.setattr(delivery, "datetime", type("Clock", (), {"now": staticmethod(lambda: datetime(2026, 1, 1, 10, 0))}))
    assert delivery.claim_legacy_notification_dispatch()
    snapshot = {}
    first, snapshot = delivery.reserve_legacy_notification_dispatch(snapshot, allow_first_dispatch=True)
    assert first
    assert not delivery.reserve_legacy_notification_dispatch(snapshot, allow_first_dispatch=True)[0]
    assert not delivery.reserve_legacy_notification_dispatch({}, allow_first_dispatch=False)[0]
    submit = Mock()
    parts = delivery.NotificationParts(_part().channel, "connection-a", "namespace-a")
    with delivery.observe_notification_progress(lambda _parts: None, claim_legacy_notice=lambda: False):
        assert not delivery.claim_legacy_notification_dispatch()
        with delivery.notification_sending_windows((rule,)):
            result = parts.send_result("opaque:recipient", 0, "正文", True, submit)
            assert result.status == "skipped" and result.code == "outside_rule_time"
            result, changed = delivery.claim_notification_part({}, result, initial_attempt=True, should_submit=True)
            assert result.status == "skipped" and changed
    submit.assert_not_called()
    assert delivery.uses_legacy_attachment_layout({"old": {}})
    deferred, _ = delivery.claim_notification_part({}, _part(), initial_attempt=True, should_submit=False)
    assert deferred.code == "previous_part_unconfirmed"


@pytest.mark.parametrize("stored", [None, {}, [None], [["connection"]], [["connection", 42]]])
def test_invalid_frozen_connection_plan_fails_closed(stored):
    """
    持久化结构含糊时停止，不扩张到当前配置。
    """
    with pytest.raises(ValueError):
        delivery.read_or_freeze_notification_connections({"_frozen_connections": stored}, None)


@pytest.mark.parametrize("stored", [None, {}, [None], [[42, []]], [["c", {}]]])
def test_invalid_frozen_rule_plan_fails_closed(stored):
    """
    损坏的规则快照不能被当前规则悄悄替换。
    """
    with pytest.raises(ValueError):
        delivery.read_or_freeze_notification_rules({"_frozen_notification_rules": stored}, {"replacement": ()})


def test_legacy_recovery_uses_only_recorded_binding_and_keeps_confirmed_digest():
    """
    旧意图仅从已有进度恢复身份，不按当前配置重新选取。
    """
    confirmed = _part(status="confirmed")
    snapshot = delivery.merge_notification_progress({}, (confirmed,))
    snapshot = delivery.merge_notification_progress(snapshot, (_part(status="retryable_failure", content_digest=None),))
    assert snapshot[delivery.notification_part_key(confirmed)]["content_digest"] == "digest-a"
    assert delivery.read_or_freeze_notification_connections(snapshot, None)[0] == frozenset({("connection-a", "namespace-a")})
    assert delivery.read_or_freeze_notification_rules(snapshot, {"new": ()}) == (None, snapshot)
    with pytest.raises(ValueError, match="无法确认"):
        delivery.read_or_freeze_notification_connections({}, None)
    snapshot = delivery.merge_notification_progress({}, (_part(status="unknown"),))
    changed = delivery.merge_notification_progress(snapshot, (_part(status="retryable_failure", content_digest=None),))
    assert changed[delivery.notification_part_key(_part())]["content_digest"] == "digest-a"


@pytest.mark.parametrize("raw,expected,reference", [
    (MessageResponse(success=True, message_id="id"), "confirmed", "id"),
    (MessageResponse(success=False), "retryable_failure", None),
    (True, "confirmed", None), (False, "retryable_failure", None),
    ((True, {"message_id": 2}), "confirmed", "2"),
    ({"ok": False}, "retryable_failure", None),
    ({"success": True}, "confirmed", None),
    ({"message_id": "id"}, "confirmed", "id"),
    ({"message_id": []}, "confirmed", None),
    (None, "unknown", None),
])
def test_confirmation_adapter_preserves_evidence(raw, expected, reference):
    """
    只有明确确认可转为成功；消息引用仅接受协议标量。
    """
    assert delivery.delivery_status(raw) == expected
    assert delivery.platform_message_id(raw) == reference
