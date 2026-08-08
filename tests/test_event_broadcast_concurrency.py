# -*- coding: utf-8 -*-
"""
回归测试：广播事件分发的并发安全（架构审计 HIGH）。

背景：``add_event_listener`` / ``remove_event_listener`` 在 ``self.__lock`` 保护下增删订阅者字典，
但 ``__dispatch_broadcast_event`` 旧实现**不持锁**直接迭代活字典 ``__broadcast_subscribers[etype].items()``。
运行时插件启停 / 热重载会在广播进行中并发改同一字典，触发
``RuntimeError: dictionary changed size during iteration``，逃出 ``__broadcast_consumer_loop``
（其 except 只捕 ``Empty``）→ 消费者线程死亡 → 广播永久停摆。

修复：
1. 广播分发在锁内对订阅者快照后再迭代（链式分发同样收口）。
2. 消费者循环对分发异常做兜底，单次异常不得杀死消费者线程。
"""
import threading
import types
from queue import PriorityQueue

from app.core.event.manager import EventManager
from app.core.event.models import Event
from app.schemas.types import EventType

_ETYPE = EventType.PluginAction  # 广播类事件（非 ChainEventType）


def _make_handler(name):
    def _handler(event):  # pragma: no cover - 不会被真正执行（executor 被替身拦截）
        return name
    _handler.__qualname__ = f"_FakeBroadcast.{name}"
    return _handler


def test_broadcast_dispatch_snapshots_subscribers_under_mutation(monkeypatch):
    """广播迭代期间并发往同一事件字典插入处理器，不应抛 RuntimeError，原处理器仍被提交。"""
    em = EventManager()
    subs = em._EventManager__broadcast_subscribers
    saved = subs.get(_ETYPE)
    subs[_ETYPE] = {"h1": _make_handler("h1"), "h2": _make_handler("h2")}
    try:
        submitted = []

        def fake_submit(func, *args):
            # 首次提交时模拟“运行时插件注册”：往正在被迭代的字典插入新键。
            if not submitted:
                subs[_ETYPE]["injected"] = _make_handler("injected")
            submitted.append(func)

        monkeypatch.setattr(em, "_EventManager__executor",
                            types.SimpleNamespace(submit=fake_submit))

        # 旧代码在此抛 RuntimeError: dictionary changed size during iteration
        em._EventManager__dispatch_broadcast_event(Event(_ETYPE))

        # 两个原始处理器都应被提交（快照在变更前已固定）
        assert len(submitted) >= 2
    finally:
        if saved is None:
            subs.pop(_ETYPE, None)
        else:
            subs[_ETYPE] = saved


def test_consumer_loop_survives_dispatch_exception(monkeypatch):
    """单次广播分发抛异常不得逃出消费者循环；后续事件仍被处理。"""
    em = EventManager()

    local_queue = PriorityQueue()
    local_queue.put((10, Event(_ETYPE)))
    local_queue.put((20, Event(_ETYPE)))
    local_event = threading.Event()
    local_event.set()

    monkeypatch.setattr(em, "_EventManager__event_queue", local_queue)
    monkeypatch.setattr(em, "_EventManager__event", local_event)

    dispatched = []

    def fake_dispatch(event):
        dispatched.append(event)
        if len(dispatched) == 1:
            raise RuntimeError("dictionary changed size during iteration")
        # 第二个事件处理完后退出循环
        local_event.clear()

    monkeypatch.setattr(em, "_EventManager__dispatch_broadcast_event", fake_dispatch)

    # 旧代码：第一个事件的 RuntimeError 会逃出 while 循环（消费者线程死亡）
    em._EventManager__broadcast_consumer_loop()

    assert len(dispatched) == 2
