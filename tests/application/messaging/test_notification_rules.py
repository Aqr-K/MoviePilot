"""
平台能力限定下的目标、受众与时间窗口规则回归。
"""

import pytest

from app.application.messaging.channel.rules import (
    routed_notification_messages,
    validate_notification_rule,
)
from app.application.messaging.channel.settings import read_channel_resources
from app.schemas.channel import NotificationRule
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType


def _rule(kind, target=None, **kwargs):
    """
    构造一条订阅通知规则。
    """
    return NotificationRule(kind=kind, target=target, message_types=(MessageType.Subscribe.value,), **kwargs)



@pytest.mark.parametrize(
    ("provider", "config", "expected"),
    [
        ("telegram", {"TELEGRAM_CHAT_ID": "-123", "TELEGRAM_TOPIC_ID": "09"}, ("conversation", "-123", "9")),
        ("qqbot", {"QQ_OPENID": "alice", "QQ_GROUP_OPENID": "groupid"}, ("conversation", "groupid", None)),
        ("feishu", {"FEISHU_OPEN_ID": "ou_alice", "FEISHU_CHAT_ID": "oc_group"}, ("user", "ou_alice", None)),
        ("wechat", {"WECHAT_MODE": "bot", "WECHAT_BOT_CHAT_ID": "GROUP:room"}, ("conversation", "room", None)),
        ("wechatclawbot", {"WECHATCLAWBOT_DEFAULT_TARGET": "wx_alice"}, ("user", "wx_alice", None)),
        ("discord", {"DISCORD_CHANNEL_ID": "123"}, ("conversation", "123", None)),
        ("slack", {"SLACK_CHANNEL": "#releases"}, ("conversation", "#releases", None)),
        ("vocechat", {"VOCECHAT_CHANNEL_ID": 123}, ("conversation", "123", None)),
    ],
)
def test_migrates_default_and_preserves_target_priority(provider, config, expected):
    """
    优先目标启用，低优先目标留在停用规则中。
    """
    snapshot = read_channel_resources(None, [{
        "id": "bot", "type": provider, "name": "bot", "enabled": True,
        "config": config, "switchs": ["订阅"],
    }])
    assert read_channel_resources(snapshot.model_dump(mode="json"), None) == snapshot
    rules = snapshot.notifications["bot"].rules
    assert rules and [rule for rule in rules if rule.enabled and rule.fallback_only] == [rules[1]]
    assert (rules[1].kind, rules[1].target, rules[1].thread_id) == expected
    assert not (set(config) - {"WECHAT_MODE"}) & set(snapshot.connections["bot"].provider_config)



def test_migration_preserves_dormant_default_and_webpush_filter():
    """
    未勾选事件的配置保留为停用。空格用户名条件不会扩大匹配范围。
    """
    snapshot = read_channel_resources(None, [
        {"id": "tg", "name": "tg", "type": "telegram", "config": {"TELEGRAM_CHAT_ID": "-123"}},
        {"id": "push", "name": "push", "type": "webpush", "switchs": ["订阅"],
         "config": {"WEBPUSH_USERNAME": " alice,bob"}},
    ])
    assert [(rule.enabled, rule.target) for rule in snapshot.notifications["tg"].rules] == [(False, None), (False, "-123")]
    assert snapshot.notifications["push"].rules[0].legacy_usernames == ("bob",)







def test_account_scope_and_event_owner_are_independent():
    """
    指定接收账号只筛选已授权受众，消息关联账号是单独条件。
    """
    conf = NotificationConf(type="webpush")
    rule = _rule("account", "recipient", owner_identity="creator")
    event = Message(mtype=MessageType.Subscribe, subscription_owner_identity="creator")
    event.set_notification_route_scope("all")
    event.targets = {"webpush": ("recipient", "other")}
    routed = list(routed_notification_messages(event, conf, (rule, rule), has_bound_target=True))
    assert [item.targets for item in routed] == [{"webpush": "recipient"}]
    event.set_notification_route_scope("user")
    event.targets = {"webpush": "other"}
    assert not list(routed_notification_messages(event, conf, (rule,), has_bound_target=True))



def test_platform_rule_rejects_ambiguous_and_cross_audience_targets():
    """
    服务器模式和目标类型在服务端独立校验。
    """
    snapshot = read_channel_resources(None, [{"id": "bot", "name": "bot", "type": "telegram"}])
    with pytest.raises(ValueError, match="个人通知"):
        _rule("conversation", "-123", audience="user")
    with pytest.raises(ValueError, match="有效的平台"):
        validate_notification_rule(snapshot.connections["bot"], _rule("user", "-123"))



@pytest.mark.parametrize("start,end,hour,minute,expected", [
    ("08:00", "22:00", 8, 0, True), ("08:00", "22:00", 22, 0, True),
    ("08:00", "22:00", 7, 59, False), ("08:00", "22:00", 22, 1, False),
    ("22:00", "06:00", 23, 0, True), ("22:00", "06:00", 5, 0, True),
    ("22:00", "06:00", 12, 0, False), ("08:00", "08:00", 1, 0, True),
])
def test_rule_sending_windows_include_boundaries_and_support_overnight(start, end, hour, minute, expected):
    """
    时间窗口使用系统本地时间，跨午夜时使用当天两侧的分钟。
    """
    from datetime import datetime

    from app.application.messaging.delivery import notification_rule_time_allows
    from app.schemas.channel import NotificationSendTime

    rule = _rule("user", "123", send_time=NotificationSendTime(start=start, end=end))
    assert notification_rule_time_allows(rule, datetime(2026, 11, 21, hour, minute)) is expected



@pytest.mark.parametrize("value", ["24:00", "9:00", "12:60", "01:00:00", "junk"])
def test_invalid_send_times_are_rejected(value):
    """
    非法窗口不能通过 API 或导入配置绕过校验。
    """
    from app.schemas.channel import NotificationSendTime

    with pytest.raises(ValueError):
        NotificationSendTime(start=value, end="22:00")



@pytest.mark.parametrize("audiences", [(), ("admin",), ("user",), ("all",), ("admin", "user"), ("admin", "all"), ("user", "all"), ("admin", "user", "all")])
@pytest.mark.parametrize("scope", ["admin", "user", "all"])
def test_multi_audience_rules_match_only_selected_global_route_classes(audiences, scope):
    """
    类别内多选取并集，空集合沿用全局，但不自行生成额外通知路由。
    """
    from app.application.messaging.channel.rules import matches_notification_rule

    rule = _rule("bound", audiences=audiences)
    event = Message(mtype=MessageType.Subscribe)
    event.set_notification_route_scope(scope)
    assert matches_notification_rule(event, rule) is (not audiences or scope in audiences)
    routed = list(routed_notification_messages(event, NotificationConf(type="telegram"), (rule,), has_bound_target=True))
    assert len(routed) == int(not audiences or scope in audiences)



@pytest.mark.parametrize("legacy,expected", [("any", ()), ("admin", ("admin",)), ("user", ("user",)), ("all", ("all",))])
def test_legacy_single_audience_rules_keep_the_same_scope(legacy, expected):
    """
    旧规则和持久化投递快照可以直接读取，不扩大原通知范围。
    """
    rule = _rule("bound", audience=legacy)
    restored = NotificationRule.model_validate_json(rule.model_dump_json())
    assert restored.matched_audiences == expected
    assert restored.audiences is None



@pytest.mark.parametrize("audiences", [[], ["admin"], ["user"], ["all", "admin"], ["all", "user"]])
def test_multi_audience_cannot_expand_platform_all_or_personal_destinations(audiences):
    """
    平台广播只能匹配全体类别，个人类别不可通过多选转发到明确第三方地址。
    """
    with pytest.raises(ValueError, match="所有用户范围|个人通知"):
        _rule("all", audiences=audiences)
    if "user" in audiences:
        with pytest.raises(ValueError, match="个人通知"):
            _rule("user", "123", audiences=audiences)
    assert _rule("all", audiences=["all"]).matched_audiences == ("all",)


def test_rule_routing_deduplicates_threads_without_expanding_personal_audience():
    """
    规则按规范会话和线程合并目标，个人范围拒绝显式群目标，绑定个人仍可投递。
    """
    rules = (_rule("conversation", "-123", thread_id="7"), _rule("conversation", "-123", thread_id="7"), _rule("conversation", "-123", thread_id="8"))
    config = NotificationConf(id="fixture", name="Fixture", type="telegram", enabled=True)
    message = Message(mtype=MessageType.Subscribe, title="订阅")
    message.set_notification_route_scope("admin")
    routed = list(routed_notification_messages(message, config, rules, has_bound_target=False))
    assert [(item.original_chat_id, item.thread_id) for item in routed] == [("-123", "7"), ("-123", "8")]
    assert message.original_chat_id is None and message.thread_id is None
    message.set_notification_route_scope("user")
    assert not list(routed_notification_messages(message, config, rules, has_bound_target=False))
    message.targets = {"telegram_userid": "42"}
    (personal,) = list(routed_notification_messages(message, config, (_rule("bound"),), has_bound_target=True))
    assert personal.targets == {"telegram_userid": "42"} and personal.original_chat_id is None
    assert not list(routed_notification_messages(message, config, (_rule("bound"),), has_bound_target=False))
    assert not list(routed_notification_messages(message, config, (_rule("user", "42", fallback_only=True),), has_bound_target=True))
