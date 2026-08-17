"""广播事件多实例隔离副本（__isolate_event）的回归测试。

覆盖两条路径：完整广播调度（__dispatch_broadcast_event，同一处理器类多个启用实例）
和 __isolate_event 自身的拷贝语义；同时验证单实例与 isolate=False（对应链式事件）
路径复用同一个事件对象，行为不受影响。
"""

import pytest

from app.runtime.events import Event, EventHandlerBinding, eventmanager
from app.schemas import ConfigChangeEventData
from app.schemas.types import ChainEventType, EventType


class _ImmediateExecutor:
    """在当前线程执行广播 handler，避免依赖真实线程池观察结果。"""

    @staticmethod
    def submit(func, *args, **kwargs):
        return func(*args, **kwargs)


class _RecordingHandler:
    """同一处理器类的实例，记录每次调用收到的事件对象。"""

    def __init__(self, tag):
        self.tag = tag
        self.received_events = []

    def on_event(self, event):
        self.received_events.append(event)


@pytest.fixture
def isolated_eventmanager(monkeypatch):
    """隔离全局事件总线的订阅表、实例解析器和广播执行器。"""
    monkeypatch.setattr(eventmanager, "_EventManager__broadcast_subscribers", {})
    monkeypatch.setattr(eventmanager, "_EventManager__chain_subscribers", {})
    monkeypatch.setattr(eventmanager, "_EventManager__handler_instance_resolvers", {})
    monkeypatch.setattr(eventmanager, "_EventManager__executor", _ImmediateExecutor())
    return eventmanager


def _register_multi_instance_handler(isolated_eventmanager, handler_cls, bindings):
    """把给定处理器类的多个实例绑定注册为 resolver，并订阅其 on_event 方法。"""

    def resolver(owner_class):
        return bindings if owner_class is handler_cls else None

    isolated_eventmanager._EventManager__handler_instance_resolvers["test"] = resolver
    isolated_eventmanager.add_event_listener(EventType.ConfigChanged, handler_cls.on_event)


def test_broadcast_dispatch_survives_multiple_enabled_instances(isolated_eventmanager):
    """同一处理器类挂两个启用实例时，广播调度不能再抛 AttributeError。"""
    instance_a = _RecordingHandler("a")
    instance_b = _RecordingHandler("b")
    bindings = [
        EventHandlerBinding(instance=instance_a, owner_name="a", instance_key="a"),
        EventHandlerBinding(instance=instance_b, owner_name="b", instance_key="b"),
    ]
    _register_multi_instance_handler(isolated_eventmanager, _RecordingHandler, bindings)

    dispatch = isolated_eventmanager._EventManager__dispatch_broadcast_event
    dispatch(Event(EventType.ConfigChanged, {"marker": "hello"}))

    assert len(instance_a.received_events) == 1
    assert len(instance_b.received_events) == 1


def test_broadcast_isolation_prevents_cross_instance_mutation(isolated_eventmanager):
    """每个实例拿到独立的 event_data 副本，事后互相修改不会串扰到对方。"""
    instance_a = _RecordingHandler("a")
    instance_b = _RecordingHandler("b")
    bindings = [
        EventHandlerBinding(instance=instance_a, owner_name="a", instance_key="a"),
        EventHandlerBinding(instance=instance_b, owner_name="b", instance_key="b"),
    ]
    _register_multi_instance_handler(isolated_eventmanager, _RecordingHandler, bindings)

    dispatch = isolated_eventmanager._EventManager__dispatch_broadcast_event
    dispatch(Event(EventType.ConfigChanged, {"marker": "hello"}))

    event_a = instance_a.received_events[0]
    event_b = instance_b.received_events[0]
    assert event_a.event_data == {"marker": "hello"}
    assert event_b.event_data == {"marker": "hello"}
    # 两份 event_data 是不同对象，而非同一个字典的共享引用
    assert event_a.event_data is not event_b.event_data

    # 事后修改互不可见，证明两个实例往后各自独立操作，不会互相污染
    event_a.event_data["only_in_a"] = True
    event_b.event_data["only_in_b"] = True
    assert "only_in_b" not in event_a.event_data
    assert "only_in_a" not in event_b.event_data


def test_single_enabled_instance_reuses_same_event_object(isolated_eventmanager, monkeypatch):
    """只有一个启用实例时直接复用调度层的事件对象，不触发隔离拷贝。"""
    instance_a = _RecordingHandler("a")
    bindings = [EventHandlerBinding(instance=instance_a, owner_name="a", instance_key="a")]
    _register_multi_instance_handler(isolated_eventmanager, _RecordingHandler, bindings)

    isolate_calls = []
    original_isolate = eventmanager._EventManager__isolate_event

    def _spy_isolate(event):
        isolate_calls.append(event)
        return original_isolate(event)

    monkeypatch.setattr(eventmanager, "_EventManager__isolate_event", _spy_isolate)

    dispatch = isolated_eventmanager._EventManager__dispatch_broadcast_event
    event = Event(EventType.ConfigChanged, {"marker": "hello"})
    dispatch(event)

    assert len(instance_a.received_events) == 1
    assert instance_a.received_events[0].event_data == {"marker": "hello"}
    # 单实例场景下 index 恒为 0，__isolate_event 不会被调用
    assert isolate_calls == []


def test_chain_dispatch_isolate_false_reuses_same_event_object(isolated_eventmanager):
    """链式事件默认 isolate=False，多个实例共用同一个事件对象，行为不回归。"""
    instance_a = _RecordingHandler("a")
    instance_b = _RecordingHandler("b")
    bindings = [
        EventHandlerBinding(instance=instance_a, owner_name="a", instance_key="a"),
        EventHandlerBinding(instance=instance_b, owner_name="b", instance_key="b"),
    ]

    def resolver(owner_class):
        return bindings if owner_class is _RecordingHandler else None

    isolated_eventmanager._EventManager__handler_instance_resolvers["test"] = resolver

    event = Event(ChainEventType.NameRecognize, {"marker": "hello"})
    isolated_eventmanager._EventManager__invoke_handler_by_type_sync(
        _RecordingHandler.on_event, event, isolate=False
    )

    assert instance_a.received_events == [event]
    assert instance_b.received_events == [event]


@pytest.mark.asyncio
async def test_async_chain_dispatch_isolate_false_reuses_same_event_object(isolated_eventmanager):
    """异步链式事件路径同样默认 isolate=False，不做隔离拷贝。"""
    instance_a = _RecordingHandler("a")
    instance_b = _RecordingHandler("b")
    bindings = [
        EventHandlerBinding(instance=instance_a, owner_name="a", instance_key="a"),
        EventHandlerBinding(instance=instance_b, owner_name="b", instance_key="b"),
    ]

    def resolver(owner_class):
        return bindings if owner_class is _RecordingHandler else None

    isolated_eventmanager._EventManager__handler_instance_resolvers["test"] = resolver

    event = Event(ChainEventType.NameRecognize, {"marker": "hello"})
    await isolated_eventmanager._EventManager__invoke_handler_by_type_async(
        _RecordingHandler.on_event, event, isolate=False
    )

    assert instance_a.received_events == [event]
    assert instance_b.received_events == [event]


def test_isolate_event_copies_dict_event_data():
    """dict 类型 event_data 做浅拷贝，返回新的 Event 且原对象不受影响。"""
    original = Event(EventType.ConfigChanged, {"marker": "hello"})

    isolated = eventmanager._EventManager__isolate_event(original)

    assert isolated is not original
    assert isolated.event_data == {"marker": "hello"}
    assert isolated.event_data is not original.event_data

    isolated.event_data["marker"] = "changed"
    assert original.event_data["marker"] == "hello"


def test_isolate_event_copies_pydantic_event_data():
    """pydantic 模型类型 event_data 用 model_copy 做浅拷贝，顶层字段互不影响。"""
    original = Event(EventType.ConfigChanged, ConfigChangeEventData(key={"A"}))

    isolated = eventmanager._EventManager__isolate_event(original)

    assert isolated is not original
    assert isolated.event_data is not original.event_data
    assert isolated.event_data.key == {"A"}

    isolated.event_data.change_type = "delete"
    assert original.event_data.change_type == "update"


def test_isolate_event_passes_through_unrecognized_data_type():
    """既非 dict 也非 pydantic 模型的 event_data 原样复用，不强行拷贝。"""

    class _OpaquePayload:
        """既不是 dict 也不是 BaseModel 的自定义载荷。"""

        def __bool__(self):
            return True

    payload = _OpaquePayload()
    original = Event(EventType.ConfigChanged, payload)

    isolated = eventmanager._EventManager__isolate_event(original)

    assert isolated is not original
    assert isolated.event_data is payload


def test_isolate_event_falls_back_to_original_on_copy_failure(monkeypatch):
    """拷贝失败时记录告警并回退为原事件对象，不能向外抛出异常。"""

    class _BoomDict(dict):
        """copy() 必定失败的 dict 子类，用于触发隔离失败分支。"""

        def copy(self):
            raise RuntimeError("boom")

    warnings = []
    monkeypatch.setattr(
        "app.runtime.events.logger.warning",
        lambda msg: warnings.append(msg),
    )
    original = Event(EventType.ConfigChanged, _BoomDict({"marker": "hello"}))

    isolated = eventmanager._EventManager__isolate_event(original)

    assert isolated is original
    assert len(warnings) == 1
