"""广播事件扇出到共享线程池前的插件并发闸门契约测试。

`EventDispatcher.dispatch_broadcast` 把插件的事件处理器提交到宿主与其余插件共用
的线程池执行；提交动作本身不受限，行为不良的插件只要让事件反复触发，就能在池里
同时占用任意多个线程，饿死其余插件与宿主自身的后台工作。闸门必须在提交前的调用
线程上取，而不是在池 worker 内部取——那样排队任务会占着池线程等待自己的信号量，
比不设闸门更糟。宿主自身的处理器不携带插件实例归属，不受这道闸门约束。
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from app.runtime.event.binding import EventHandlerBinding
from app.runtime.event.dispatch import EventDispatcher
from app.runtime.extensions.plugin_quota import (
    PLUGIN_QUOTA_BROADCAST_WAIT_TIMEOUT,
    PLUGIN_QUOTA_WAIT_TIMEOUT,
    PluginExecutionQuota,
)
from app.schemas.types import EventType


class _FakeRegistry:
    """把固定的 `(handler_id, handler)` 广播快照喂给调度器的替身。"""

    def __init__(self, handler):
        self._handler = handler

    def broadcast_snapshot(self, _event_type):
        return (("app.plugins.demo.DemoPlugin.on_event", self._handler),)

    @staticmethod
    def is_handler_enabled(_handler):
        return True


class _FixedBindingResolver:
    """把处理器解析为固定绑定列表的替身，模拟插件或宿主的归属判定结果。"""

    def __init__(self, bindings):
        self._bindings = bindings

    def resolve(self, _handler):
        return self._bindings


def _broadcast_event():
    return SimpleNamespace(
        event_type=EventType.ConfigChanged,
        event_data={},
        priority=10,
    )


def _build_dispatcher(*, handler, bindings, plugin_quota, pool):
    return EventDispatcher(
        registry=_FakeRegistry(handler),
        binding_resolver=_FixedBindingResolver(bindings),
        executor=lambda: pool,
        event_loop=lambda: None,
        event_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        error_handler=lambda **kwargs: None,
        plugin_quota=plugin_quota,
    )


def _blocking_handler(state, lock, release):
    """占位耗时处理器：记录同时在场人数，等外部信号后才退出。"""

    def handler(_event):
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        release.wait(timeout=5)
        with lock:
            state["live"] -= 1

    return handler


def test_dispatch_broadcast_caps_concurrent_threads_for_same_plugin_handler():
    """同一插件的处理器被多个事件反复触发时，同时占用的池线程不超过它的配额。"""
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()
    release = threading.Event()
    handler = _blocking_handler(state, lock, release)
    binding = EventHandlerBinding(
        instance=object(),
        owner_name="DemoPlugin",
        instance_key="DemoPlugin",
    )
    quota = PluginExecutionQuota(capacity_provider=lambda: 2, wait_timeout=5)
    pool = ThreadPoolExecutor(max_workers=6)
    dispatcher = _build_dispatcher(
        handler=handler,
        bindings=[(handler, binding, "DemoPlugin", "on_event")],
        plugin_quota=quota,
        pool=pool,
    )

    try:
        for _ in range(6):
            dispatcher.dispatch_broadcast(_broadcast_event())
        time.sleep(0.3)
        assert state["peak"] <= 2
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_broadcast_wait_timeout_is_far_below_the_coroutine_path():
    """广播路径的等待超时必须远小于协程路径，取槽阻塞的是唯一的消费者线程。"""
    assert PLUGIN_QUOTA_BROADCAST_WAIT_TIMEOUT < PLUGIN_QUOTA_WAIT_TIMEOUT / 10


def test_dispatch_broadcast_admits_quickly_when_quota_is_saturated():
    """配额被占满时提交动作按广播超时放行，不把消费者线程长时间钉住。"""
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()
    release = threading.Event()
    handler = _blocking_handler(state, lock, release)
    binding = EventHandlerBinding(
        instance=object(),
        owner_name="DemoPlugin",
        instance_key="DemoPlugin",
    )
    quota = PluginExecutionQuota(
        capacity_provider=lambda: 1,
        wait_timeout=PLUGIN_QUOTA_BROADCAST_WAIT_TIMEOUT,
    )
    pool = ThreadPoolExecutor(max_workers=4)
    dispatcher = _build_dispatcher(
        handler=handler,
        bindings=[(handler, binding, "DemoPlugin", "on_event")],
        plugin_quota=quota,
        pool=pool,
    )

    try:
        dispatcher.dispatch_broadcast(_broadcast_event())
        started = time.monotonic()
        dispatcher.dispatch_broadcast(_broadcast_event())
        blocked = time.monotonic() - started
        assert blocked < PLUGIN_QUOTA_BROADCAST_WAIT_TIMEOUT * 3
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_dispatch_broadcast_does_not_gate_host_handlers():
    """宿主自身的处理器（绑定不携带 `instance_key`）不受插件配额约束。"""
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()
    release = threading.Event()
    handler = _blocking_handler(state, lock, release)
    binding = EventHandlerBinding(instance=object(), owner_name="Scheduler")
    quota = PluginExecutionQuota(capacity_provider=lambda: 2, wait_timeout=5)
    pool = ThreadPoolExecutor(max_workers=6)
    dispatcher = _build_dispatcher(
        handler=handler,
        bindings=[(handler, binding, "Scheduler", "on_event")],
        plugin_quota=quota,
        pool=pool,
    )

    try:
        for _ in range(6):
            dispatcher.dispatch_broadcast(_broadcast_event())
        time.sleep(0.3)
        assert state["peak"] == 6
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_dispatch_broadcast_releases_slot_after_handler_raises():
    """处理器抛异常也要归还槽位，否则配额会被异常路径逐次漏光。"""
    calls = {"count": 0}
    lock = threading.Lock()

    def failing_handler(_event):
        with lock:
            calls["count"] += 1
        raise RuntimeError("boom")

    errors = []
    binding = EventHandlerBinding(
        instance=object(),
        owner_name="DemoPlugin",
        instance_key="DemoPlugin",
    )
    quota = PluginExecutionQuota(capacity_provider=lambda: 1, wait_timeout=1)
    pool = ThreadPoolExecutor(max_workers=4)
    dispatcher = EventDispatcher(
        registry=_FakeRegistry(failing_handler),
        binding_resolver=_FixedBindingResolver(
            [(failing_handler, binding, "DemoPlugin", "on_event")]
        ),
        executor=lambda: pool,
        event_loop=lambda: None,
        event_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        error_handler=lambda **kwargs: errors.append(kwargs),
        plugin_quota=quota,
    )

    try:
        for _ in range(3):
            dispatcher.dispatch_broadcast(_broadcast_event())
        pool.shutdown(wait=True)
        assert calls["count"] == 3
        assert len(errors) == 3
    finally:
        pool.shutdown(wait=True)
