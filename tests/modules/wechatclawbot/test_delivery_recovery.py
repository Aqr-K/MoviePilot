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
from app.modules.wechatclawbot import WechatClawBotModule
from app.modules.wechatclawbot.wechatclawbot import ILinkClient, WechatClawBot
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
@pytest.mark.parametrize("transient", [True, False])
def test_clawbot_durable_text_recovery_uses_one_protocol_address(monkeypatch, transient, managed):
    """
    iLink 限流仅补发未发分段，响应丢失不会触发兼容报文或地址回退。
    """
    sender = ILinkClient("https://ilink.example", "fixture-token", "fixture-bot")
    bot = WechatClawBot.__new__(WechatClawBot)
    bot._default_target = None
    bot._state = {"known_targets": {"unconfigured": {}}}
    monkeypatch.setattr(bot, "_build_client", lambda: sender)
    acknowledged = Mock(status_code=200, content=b'{"ret":0}', **{"json.return_value": {"ret": 0}})
    post = Mock(side_effect=[acknowledged, Mock(status_code=429) if transient else None, acknowledged])
    monkeypatch.setattr("app.modules.wechatclawbot.wechatclawbot.RequestUtils", Mock(**{"return_value.post_res": post}))
    module = WechatClawBotModule()
    module._channel = NotificationChannel.WechatClawBot
    conf = NotificationConf(id="claw", name="claw", type="wechatclawbot", enabled=True, identity_namespace="binding")
    monkeypatch.setattr(module, "get_configs", lambda: {conf.name: conf})
    monkeypatch.setattr(module, "get_config", lambda _: conf)
    monkeypatch.setattr(module, "get_instance", lambda _: bot)
    progress = {}

    def deliver(*, initial, target="alice"):
        """
        以发送模块的真实入口投递长文本。
        """
        message = Message(channel=NotificationChannel.WechatClawBot, userid=target, text="甲" * 1200)
        if not target:
            message.set_notification_route_scope("all")
        results = message.collect_delivery_results()
        with _observe_recovery(progress, initial=initial) if managed else nullcontext():
            module.post_message(message)
        return [result.status for result in results]

    assert deliver(initial=True) == ["confirmed", "retryable_failure" if transient else "unknown"]
    if managed:
        assert deliver(initial=False) == ["confirmed", "confirmed" if transient else "unknown"]
    assert deliver(initial=False, target=None) == ["skipped"]
    assert post.call_count == (3 if transient and managed else 2)
    assert all(call.kwargs["json"]["msg"]["to_user_id"] == "alice" for call in post.call_args_list)
    assert all(call.args[0] == "https://ilink.example/ilink/bot/sendmessage" for call in post.call_args_list)
