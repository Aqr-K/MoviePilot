"""插件同步方法卸载与插件执行配额。

两条都围绕「插件不该拖垮宿主」：

- 协程里直接调用同步插件方法，插件里任何阻塞或 CPU 密集代码都会卡住事件循环，
  必须卸载到线程；
- 插件占用共享线程的数量若不设上限，一个行为不良的插件能吃光整个池子，饿死其余
  插件和宿主自身的后台工作，因此每个插件要有自己的并发闸门。

闸门按插件类而非运行实例发放：同一插件的多个实例跑的是同一份代码、同一种故障模式，
按实例发放等于让插件通过增开实例线性放大自己的份额。
"""

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from app.foundation.singleton import Singleton
from app.runtime.config import settings
from app.runtime.extensions import plugin_quota as quota_module
from app.runtime.extensions.plugin_quota import (
    PLUGIN_QUOTA_MIN_SLOTS,
    PLUGIN_QUOTA_POOL_DIVISOR,
    PluginExecutionQuota,
    resolve_plugin_quota_capacity,
)
from app.runtime.extensions.plugin_manager import PluginManager


@pytest.fixture
def plugin_manager():
    """构造隔离的插件管理器，供配额与卸载用例登记运行实例。"""
    Singleton._instances.pop((PluginManager, (), frozenset()), None)
    manager = PluginManager()
    yield manager
    Singleton._instances.pop((PluginManager, (), frozenset()), None)


def _quota(capacity: int, *, wait_timeout: float = 0.2) -> PluginExecutionQuota:
    """构造固定容量、短超时的配额，避免用例依赖机器配置与真实等待时长。"""
    return PluginExecutionQuota(
        capacity_provider=lambda: capacity,
        wait_timeout=wait_timeout,
        poll_interval=0.005,
    )


# --------------------------------------------------------------------------- #
# 同步插件方法卸载
# --------------------------------------------------------------------------- #

def test_async_run_plugin_method_offloads_sync_method_off_event_loop(plugin_manager):
    """同步插件方法必须在事件循环之外执行，否则插件里的阻塞会卡死整个宿主。"""

    class _Carrier:
        def ping(self) -> int:
            return threading.get_ident()

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    async def scenario():
        loop_thread = threading.get_ident()
        worker_thread = await plugin_manager.async_run_plugin_method(
            "PluginQ@default", "ping"
        )
        return loop_thread, worker_thread

    loop_thread, worker_thread = asyncio.run(scenario())

    assert worker_thread != loop_thread


def test_async_run_plugin_method_awaits_coroutine_method_on_event_loop(plugin_manager):
    """协程插件方法直接 await，不额外占用线程。"""

    class _Carrier:
        async def ping(self) -> int:
            return threading.get_ident()

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    async def scenario():
        loop_thread = threading.get_ident()
        handler_thread = await plugin_manager.async_run_plugin_method(
            "PluginQ@default", "ping"
        )
        return loop_thread, handler_thread

    loop_thread, handler_thread = asyncio.run(scenario())

    assert handler_thread == loop_thread


def test_async_run_plugin_method_passes_arguments_and_returns_value(plugin_manager):
    """卸载后位置参数、关键字参数与返回值的语义与同步孪生一致。"""

    class _Carrier:
        def add(self, left: int, *, right: int = 0) -> int:
            return left + right

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    result = asyncio.run(
        plugin_manager.async_run_plugin_method("PluginQ@default", "add", 2, right=3)
    )

    assert result == 5
    assert plugin_manager.run_plugin_method("PluginQ@default", "add", 2, right=3) == 5


def test_async_run_plugin_method_propagates_sync_method_exception(plugin_manager):
    """卸载不吞异常：插件方法抛什么，调用方就收到什么。"""

    class _Carrier:
        def boom(self) -> None:
            raise ValueError("插件炸了")

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    with pytest.raises(ValueError, match="插件炸了"):
        asyncio.run(plugin_manager.async_run_plugin_method("PluginQ@default", "boom"))


def test_async_run_plugin_method_keeps_missing_target_semantics(plugin_manager):
    """插件未运行或未实现该方法时仍返回 None，不因卸载改成抛错。"""

    class _Carrier:
        def ping(self) -> str:
            return "pong"

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    async def scenario():
        missing_plugin = await plugin_manager.async_run_plugin_method("PluginZ", "ping")
        missing_method = await plugin_manager.async_run_plugin_method(
            "PluginQ@default", "nope"
        )
        return missing_plugin, missing_method

    missing_plugin, missing_method = asyncio.run(scenario())

    assert missing_plugin is None
    assert missing_method is None


# --------------------------------------------------------------------------- #
# 配额容量
# --------------------------------------------------------------------------- #

def test_quota_capacity_follows_threadpool_share(monkeypatch):
    """单个插件的槽位数按共享线程池容量的固定份额派生。"""
    monkeypatch.setattr(
        type(settings), "CONF", property(lambda self: SimpleNamespace(threadpool=100))
    )

    assert resolve_plugin_quota_capacity() == 100 // PLUGIN_QUOTA_POOL_DIVISOR


def test_quota_capacity_has_lower_bound(monkeypatch):
    """线程池极小时仍保底若干槽位，插件不会一个任务都跑不动。"""
    monkeypatch.setattr(
        type(settings), "CONF", property(lambda self: SimpleNamespace(threadpool=1))
    )

    assert resolve_plugin_quota_capacity() == PLUGIN_QUOTA_MIN_SLOTS


# --------------------------------------------------------------------------- #
# 配额闸门
# --------------------------------------------------------------------------- #

def test_quota_caps_concurrent_slots_of_one_plugin():
    """同一插件的并发占用不超过它自己的槽位数。"""
    quota = _quota(2, wait_timeout=5)
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()

    async def occupy():
        async with quota.async_slot("PluginA"):
            with lock:
                state["live"] += 1
                state["peak"] = max(state["peak"], state["live"])
            await asyncio.sleep(0.02)
            with lock:
                state["live"] -= 1

    async def scenario():
        await asyncio.gather(*(occupy() for _ in range(8)))

    asyncio.run(scenario())

    assert state["peak"] == 2


def test_quota_does_not_couple_different_plugins():
    """一个插件占满自己的槽位不会挡住别的插件。"""
    quota = _quota(1, wait_timeout=5)
    order = []

    async def scenario():
        async with quota.async_slot("PluginA"):
            order.append("A-held")
            async with quota.async_slot("PluginB"):
                order.append("B-acquired")

    asyncio.run(scenario())

    assert order == ["A-held", "B-acquired"]


def test_quota_is_shared_across_instances_of_the_same_plugin(plugin_manager):
    """同一插件的多个实例共用一份配额，增开实例放大不了自己的份额。"""
    plugin_manager._execution_quota = _quota(1, wait_timeout=5)
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()

    class _Carrier:
        def work(self) -> None:
            with lock:
                state["live"] += 1
                state["peak"] = max(state["peak"], state["live"])
            time.sleep(0.02)
            with lock:
                state["live"] -= 1

    plugin_manager._running_plugins["PluginQ@one"] = _Carrier()
    plugin_manager._running_plugins["PluginQ@two"] = _Carrier()

    async def scenario():
        await asyncio.gather(
            plugin_manager.async_run_plugin_method("PluginQ@one", "work"),
            plugin_manager.async_run_plugin_method("PluginQ@two", "work"),
        )

    asyncio.run(scenario())

    assert state["peak"] == 1


def test_quota_gates_the_offloaded_plugin_call(plugin_manager):
    """闸门装在卸载路径上：同插件的并发卸载受槽位数约束。"""
    plugin_manager._execution_quota = _quota(1, wait_timeout=5)
    state = {"live": 0, "peak": 0}
    lock = threading.Lock()

    class _Carrier:
        def work(self) -> None:
            with lock:
                state["live"] += 1
                state["peak"] = max(state["peak"], state["live"])
            time.sleep(0.02)
            with lock:
                state["live"] -= 1

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()

    async def scenario():
        await asyncio.gather(
            *(
                plugin_manager.async_run_plugin_method("PluginQ@default", "work")
                for _ in range(4)
            )
        )

    asyncio.run(scenario())

    assert state["peak"] == 1


def test_quota_wait_timeout_warns_with_plugin_name_and_admits(monkeypatch):
    """槽位等不到时点名插件记录告警并放行，不静默丢弃插件调用。"""
    warnings = []
    monkeypatch.setattr(
        quota_module, "logger", SimpleNamespace(warn=warnings.append)
    )
    quota = _quota(1, wait_timeout=0.05)
    executed = []

    async def scenario():
        async with quota.async_slot("PluginA") as first:
            async with quota.async_slot("PluginA") as second:
                executed.append("ran")
            return first, second

    first, second = asyncio.run(scenario())

    assert first is True
    assert second is False
    assert executed == ["ran"]
    assert any("PluginA" in message for message in warnings)


def test_quota_slot_is_returned_after_body_raises():
    """插件方法抛异常也要归还槽位，否则配额会被异常路径逐次漏光。"""
    quota = _quota(1, wait_timeout=0.05)

    async def scenario():
        with pytest.raises(RuntimeError):
            async with quota.async_slot("PluginA"):
                raise RuntimeError("boom")
        async with quota.async_slot("PluginA") as acquired:
            return acquired

    assert asyncio.run(scenario()) is True


# --------------------------------------------------------------------------- #
# 配额记录的回收
# --------------------------------------------------------------------------- #

def test_quota_record_is_dropped_when_last_instance_stops(plugin_manager):
    """插件最后一个实例停止后释放其配额记录，映射不会随插件启停无界增长。"""

    class _Carrier:
        def ping(self) -> str:
            return "pong"

    plugin_manager._running_plugins["PluginQ@one"] = _Carrier()
    plugin_manager._running_plugins["PluginQ@two"] = _Carrier()
    asyncio.run(plugin_manager.async_run_plugin_method("PluginQ@one", "ping"))
    assert "PluginQ" in plugin_manager._execution_quota.tracked_plugins()

    plugin_manager.stop("PluginQ", instance_id="one")
    assert "PluginQ" in plugin_manager._execution_quota.tracked_plugins()

    plugin_manager.stop("PluginQ", instance_id="two")
    assert "PluginQ" not in plugin_manager._execution_quota.tracked_plugins()


def test_quota_records_are_dropped_when_all_plugins_stop(plugin_manager, monkeypatch):
    """全量停止插件后不留任何配额记录。"""
    # 全量停止会连带清空 sys.modules 里的插件模块缓存，那是本用例之外的关注点，
    # 且会波及同一进程内其他用例已导入的插件类，这里替换掉只留配额释放路径。
    monkeypatch.setattr(plugin_manager, "_clear_plugin_modules", lambda *_a, **_kw: None)

    class _Carrier:
        def ping(self) -> str:
            return "pong"

    plugin_manager._running_plugins["PluginQ@default"] = _Carrier()
    plugin_manager._running_plugins["PluginR@default"] = _Carrier()
    asyncio.run(plugin_manager.async_run_plugin_method("PluginQ@default", "ping"))
    asyncio.run(plugin_manager.async_run_plugin_method("PluginR@default", "ping"))
    assert len(plugin_manager._execution_quota.tracked_plugins()) == 2

    plugin_manager.stop()

    assert plugin_manager._execution_quota.tracked_plugins() == ()
