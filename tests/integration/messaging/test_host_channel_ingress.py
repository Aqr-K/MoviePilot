"""
已认证 SDK 绑定的提交拒绝、生命周期与事件认领回归。
"""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.application.messaging import ingress
from app.application.security import authorization
from app.schemas.channel import InteractionPolicy
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel


@pytest.fixture
def ready_ingress(monkeypatch):
    """
    只替换队列边界；真实授权与规则调用链由独立平台共存回归另行覆盖。
    """
    receiver = Mock()
    monkeypatch.setattr(ingress, "_platform_payload_receiver", receiver)
    monkeypatch.setattr(authorization, "get_channel_authorization", lambda: object())
    monkeypatch.setattr(ingress, "runtime_stop_state", SimpleNamespace(is_system_stopped=False))
    return receiver



def _identity():
    """
    返回宿主已装配的合成连接元数据，不含平台凭据。
    """
    return dict(
        source="channel", channel=NotificationChannel.Telegram, connection_id="connection",
        provider="telegram", identity_namespace="namespace", parser_owner="TelegramModule", policy_revision=4,
    )



@pytest.mark.parametrize("missing", ["connection_id", "provider", "identity_namespace", "parser_owner", "policy_revision"])
def test_incomplete_bound_identity_is_rejected_without_submission(ready_ingress, monkeypatch, missing):
    """
    所有必要身份字段都必须来自装配，不从报文补齐，也不走备用路径。
    """
    values = _identity()
    values[missing] = None
    submit = Mock()
    log = Mock()
    monkeypatch.setattr(ingress.logger, "warning", log)
    assert ingress.submit_platform_payload({"provider": "telegram", "connection_id": "connection"}, submit=submit, **values) is False
    submit.assert_not_called()
    ready_ingress.assert_not_called()
    assert "reason=identity_missing," in log.call_args.args[0]



@pytest.mark.parametrize("unavailable", ["receiver", "authorization", "stopping"])
def test_unready_or_stopping_ingress_fails_closed(ready_ingress, monkeypatch, unavailable):
    """
    解析器装配、通用授权及进程生命周期均须就绪，才能接收 SDK 事件。
    """
    if unavailable == "receiver":
        monkeypatch.setattr(ingress, "_platform_payload_receiver", None)
    elif unavailable == "authorization":
        monkeypatch.setattr(authorization, "get_channel_authorization", lambda: None)
    else:
        monkeypatch.setattr(ingress, "runtime_stop_state", SimpleNamespace(is_system_stopped=True))
    submit = Mock()
    assert ingress.submit_platform_payload({}, submit=submit, **_identity()) is False
    submit.assert_not_called()
    ready_ingress.assert_not_called()



@pytest.mark.parametrize("reserved", [NotificationChannel.Web, NotificationChannel.WebAgent])
def test_host_web_identity_cannot_be_used_by_sdk_ingress(ready_ingress, reserved):
    """
    即使提供其它元数据，宿主网页身份也不能用于外部 SDK 的事件入口。
    """
    values = _identity() | {"channel": reserved}
    submit = Mock()
    assert ingress.submit_platform_payload({}, submit=submit, **values) is False
    submit.assert_not_called()



@pytest.mark.parametrize("change", ["stopping", "reset", "replacement"])
def test_queued_event_cannot_outlive_receiver_lifecycle(ready_ingress, monkeypatch, change):
    """
    接受后的排队任务在执行前仍须检查封口及接收器代际，不能切换传输补发。
    """
    submit = Mock(return_value=True)
    assert ingress.submit_platform_payload({"event": "one"}, submit=submit, **_identity()) is True
    call = submit.call_args.args
    if change == "stopping":
        monkeypatch.setattr(ingress, "runtime_stop_state", SimpleNamespace(is_system_stopped=True))
    else:
        monkeypatch.setattr(ingress, "_platform_payload_receiver", None if change == "reset" else Mock())
    call[0](*call[1:])
    ready_ingress.assert_not_called()
    assert submit.call_count == 1



def test_binding_freezes_connection_owner_namespace_revision_and_ignores_payload_spoofing(ready_ingress):
    """
    宿主冻结的连接事实不受配置对象后续修改或报文伪造影响，实际处理仍复核当前配置。
    """
    config = NotificationConf(
        id="connection", name="channel", type="telegram", identity_namespace="namespace", enabled=True,
        interaction_policy=InteractionPolicy(
            connection_id="connection", identity_namespace="namespace", revision=4, enabled=True,
        ),
    )
    bound = ingress.bind_platform_payload(config)
    assert bound is not None
    config.id, config.name, config.type, config.identity_namespace = "other", "renamed", "discord", "other"
    submit = Mock(return_value=True)
    payload = {"provider": "discord", "namespace": "other", "connection_id": "other"}
    assert bound(payload, submit=submit)
    call = submit.call_args.args
    assert call[1] is ready_ingress and json.loads(call[2]) == payload
    assert call[3:] == ("channel", NotificationChannel.Telegram, "connection", "telegram", "namespace", "TelegramModule", 4)



@pytest.mark.parametrize("outcome", [False, RuntimeError("closed"), ValueError("failed")])
def test_submit_rejection_or_exception_never_invokes_receiver(ready_ingress, outcome):
    """
    执行器拒绝和异常都只返回失败，不能同步重试或切换到其它传输。
    """
    submit = Mock(return_value=outcome if not isinstance(outcome, Exception) else None)
    if isinstance(outcome, Exception):
        submit.side_effect = outcome
    assert ingress.submit_platform_payload({}, submit=submit, **_identity()) is False
    submit.assert_called_once()
    ready_ingress.assert_not_called()



def test_bound_entry_exception_is_diagnosed_without_retry_or_sensitive_details(ready_ingress, monkeypatch):
    """
    绑定入口异常只提交一次并记录错误类型，不回环或把可能含凭据的异常正文写入日志。
    """
    bound = Mock(side_effect=RuntimeError("fixture-private-token"))
    submit = Mock()
    legacy = Mock()
    log = Mock()
    monkeypatch.setattr(ingress, "forward_message_to_host", legacy)
    monkeypatch.setattr(ingress.logger, "warning", log)
    assert ingress.submit_bound_payload({"text": "申请使用"}, bound, "fixture", submit=submit) is False
    bound.assert_called_once_with({"text": "申请使用"}, submit=submit)
    submit.assert_not_called()
    legacy.assert_not_called()
    ready_ingress.assert_not_called()
    assert "reason=submit_failed:RuntimeError," in log.call_args.args[0]
    assert "fixture-private-token" not in str(log.call_args)



def test_offline_claim_is_connection_scoped_bounded_and_expires(monkeypatch):
    """
    未装配共享认领服务的隔离入口按连接防重，缓存满时拒绝新事件，过期后才释放容量。
    """
    from cachetools import TTLCache

    from app.domain.admission import AdmissionProof

    clock = [100.0]
    cache = TTLCache(maxsize=2, ttl=120, timer=lambda: clock[0])
    monkeypatch.setattr(ingress, "time", SimpleNamespace(time=lambda: clock[0]))
    monkeypatch.setattr(ingress, "_verified_events", cache)
    monkeypatch.setattr(ingress, "_verified_event_claim", None)
    first = AdmissionProof("first", 1, "alice", None, 1000)
    second = AdmissionProof("second", 1, "alice", None, 1000)
    assert ingress.claim_verified_event(first, "event-one") is True
    assert ingress.claim_verified_event(first, "event-one") is False
    assert ingress.claim_verified_event(second, "event-one") is True
    assert ingress.claim_verified_event(first, "event-two") is False
    assert len(cache) == cache.maxsize
    clock[0] = 221
    assert ingress.claim_verified_event(first, "event-two") is True
    assert len(cache) == 1



def test_notification_only_connection_has_no_sdk_binding():
    """
    仅投递连接不装配可信入站能力，公共类型和构造参数不能自动启用交互。
    """
    config = NotificationConf(id="only-notify", name="notify", type="telegram", enabled=True, interaction_enabled=False)
    assert ingress.bind_platform_payload(config) is None



@pytest.mark.parametrize("status", ["already_cancelled", "cancel_later", "failed_later"])
def test_async_submission_failures_are_diagnosed_without_retry(ready_ingress, monkeypatch, status):
    """
    受管 Future 的取消和异步失败也须可诊断，不能触发 HTTP 或第二次提交。
    """
    from concurrent.futures import Future

    future = Future()
    log = Mock()
    monkeypatch.setattr(ingress.logger, "warning", log)
    if status == "already_cancelled":
        future.cancel()
    submit = Mock(return_value=future)
    accepted = ingress.submit_platform_payload({}, submit=submit, **_identity())
    assert accepted is (status != "already_cancelled")
    if status == "cancel_later":
        future.cancel()
    elif status == "failed_later":
        future.set_exception(RuntimeError("worker failed"))
    assert any(f"reason={reason}," in log.call_args.args[0] for reason in (
        "submit_rejected", "submission_cancelled", "processing_failed:RuntimeError",
    ))
    submit.assert_called_once()
    ready_ingress.assert_not_called()
