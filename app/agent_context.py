import contextvars
from contextlib import contextmanager
from typing import Iterator

_suppress_message_channel_dispatch = contextvars.ContextVar(
    "suppress_message_channel_dispatch",
    default=False,
)


def is_message_channel_dispatch_suppressed() -> bool:
    """
    当前 Agent 执行上下文是否禁止向外部消息渠道派发通知。
    """
    return bool(_suppress_message_channel_dispatch.get())


@contextmanager
def agent_execution_context(
    *, suppress_message_channel_dispatch: bool = False
) -> Iterator[None]:
    """
    绑定当前 Agent 执行期的上下文参数。
    """
    token = _suppress_message_channel_dispatch.set(
        bool(suppress_message_channel_dispatch)
    )
    try:
        yield
    finally:
        _suppress_message_channel_dispatch.reset(token)
