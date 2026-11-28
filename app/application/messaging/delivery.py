"""
通知规则发送窗口与冻结上下文的通用投递边界。
"""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime

from app.schemas.channel import NotificationRule, NotificationSendTime

type FrozenNotificationRules = Mapping[str, tuple[NotificationRule, ...]]

_frozen_rules: ContextVar[FrozenNotificationRules | None] = ContextVar("frozen_notification_rules", default=None)
_sending_windows: ContextVar[tuple[NotificationSendTime | None, ...] | None] = ContextVar("notification_sending_windows", default=None)


def notification_rule_time_allows(rule: NotificationRule, now: datetime | None = None) -> bool:
    """
    使用系统本地时区判断规则的发送窗口。
    """
    return rule.send_time is None or rule.send_time.allows(now or datetime.now())



def notification_rules_are_frozen() -> bool:
    """
    判断当前派发是否沿用持久化规则快照。
    """
    return _frozen_rules.get() is not None



@contextmanager
def notification_sending_windows(rules: tuple[NotificationRule, ...]) -> Iterator[None]:
    """
    同一目标命中多条规则时，任一时间窗口允许即可发送。
    """
    token = _sending_windows.set(tuple(rule.send_time for rule in rules))
    try:
        yield
    finally:
        _sending_windows.reset(token)
