import contextvars
from contextlib import contextmanager
from typing import Iterator

_suppress_message_channel = contextvars.ContextVar(
    "suppress_message_channel", default=False
)


def is_message_channel_suppressed() -> bool:
    """
    当前上下文是否禁止向外部消息渠道派发通知。
    """
    return bool(_suppress_message_channel.get())


@contextmanager
def suppress_message_channel() -> Iterator[None]:
    """
    在当前上下文中临时禁用外部消息渠道派发。
    """
    token = _suppress_message_channel.set(True)
    try:
        yield
    finally:
        _suppress_message_channel.reset(token)
