"""WEB 消息入口异步路由的线程卸载契约测试。"""

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

from app.api.endpoints import message as message_endpoint


def test_web_message_offloads_message_chain_handling(monkeypatch):
    """WEB 消息处理触发的 MessageChain 同步链路必须卸载到线程池，不能阻塞事件循环。"""
    calls = []

    async def fake_run_in_threadpool(func, *args, **kwargs):
        calls.append((func, args, kwargs))
        return func(*args, **kwargs)

    fake_chain = Mock()
    monkeypatch.setattr(message_endpoint, "run_in_threadpool", fake_run_in_threadpool)
    monkeypatch.setattr(message_endpoint, "MessageChain", Mock(return_value=fake_chain))

    request = Mock()
    request.headers = {"content-type": "text/plain"}
    current_user = SimpleNamespace(name="tester")

    response = asyncio.run(
        message_endpoint.web_message(
            request=request, text="hello", current_user=current_user
        )
    )

    assert response.success is True
    fake_chain.handle_message.assert_called_once_with(
        channel=message_endpoint.NotificationChannel.Web,
        source="tester",
        userid="tester",
        username="tester",
        text="hello",
        images=None,
    )
    assert calls == [
        (
            fake_chain.handle_message,
            (),
            {
                "channel": message_endpoint.NotificationChannel.Web,
                "source": "tester",
                "userid": "tester",
                "username": "tester",
                "text": "hello",
                "images": None,
            },
        )
    ]
