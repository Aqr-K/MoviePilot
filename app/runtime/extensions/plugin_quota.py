"""插件执行配额：限制单个插件同时占用的共享线程数。"""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncIterator, Callable, Dict, Iterator, Tuple

from app.runtime.config import settings
from app.runtime.log import logger

# 单个插件可占用的共享线程池份额分母
PLUGIN_QUOTA_POOL_DIVISOR = 4
# 单个插件的槽位下限，保证线程池极小时插件仍能推进
PLUGIN_QUOTA_MIN_SLOTS = 2
# 等待空闲槽位的超时秒数
PLUGIN_QUOTA_WAIT_TIMEOUT = 60.0
# 广播扇出路径等待空闲槽位的超时秒数。该路径在唯一的广播消费者线程上取槽，
# 等待期间全部排队事件都停止分发，因此超时必须远小于协程路径的取值：
# 宁可让占满配额的插件短暂突破上限，也不能让一个插件拖停整条事件总线
PLUGIN_QUOTA_BROADCAST_WAIT_TIMEOUT = 1.0
# 异步等待空闲槽位时的重试间隔秒数
PLUGIN_QUOTA_POLL_INTERVAL = 0.05


def resolve_plugin_quota_capacity() -> int:
    """计算单个插件的并发执行槽位数。

    :return: 共享线程池容量按 `PLUGIN_QUOTA_POOL_DIVISOR` 取的份额，
        不低于 `PLUGIN_QUOTA_MIN_SLOTS`
    """
    share = settings.CONF.threadpool // PLUGIN_QUOTA_POOL_DIVISOR
    return max(PLUGIN_QUOTA_MIN_SLOTS, share)


class PluginExecutionQuota:
    """按插件类维护并发执行闸门。

    槽位按插件类而非运行实例发放：同一插件的多个实例跑的是同一份代码、同一种故障
    模式，按实例发放等于让插件通过增开实例线性放大自己的份额。

    闸门用 `threading.BoundedSemaphore` 记账而非事件循环原语，因此同一份配额可以
    同时被协程路径和线程路径申领，也不会随事件循环重建而失效。
    """

    def __init__(
        self,
        capacity_provider: Callable[[], int] = resolve_plugin_quota_capacity,
        wait_timeout: float = PLUGIN_QUOTA_WAIT_TIMEOUT,
        poll_interval: float = PLUGIN_QUOTA_POLL_INTERVAL,
    ) -> None:
        """按容量来源与等待策略初始化闸门映射。

        :param capacity_provider: 单个插件槽位数的取值来源
        :param wait_timeout: 等待空闲槽位的超时秒数
        :param poll_interval: 异步等待空闲槽位时的重试间隔秒数
        """
        self._capacity_provider = capacity_provider
        self._wait_timeout = wait_timeout
        self._poll_interval = poll_interval
        self._lock = threading.Lock()
        self._gates: Dict[str, Tuple[threading.BoundedSemaphore, int]] = {}

    def gate(self, plugin_id: str) -> Tuple[threading.BoundedSemaphore, int]:
        """取插件的闸门，没有记录时按当前容量新建。

        :param plugin_id: 插件标识
        :return: `(信号量, 槽位数)`
        """
        with self._lock:
            entry = self._gates.get(plugin_id)
            if entry is None:
                capacity = max(1, int(self._capacity_provider()))
                entry = (threading.BoundedSemaphore(capacity), capacity)
                self._gates[plugin_id] = entry
            return entry

    def tracked_plugins(self) -> Tuple[str, ...]:
        """列出当前持有配额记录的插件标识。

        :return: 插件标识元组
        """
        with self._lock:
            return tuple(self._gates)

    def discard(self, plugin_id: str) -> None:
        """丢弃插件的配额记录。

        已借出的槽位由持有者按原信号量对象归还，不受丢弃影响。
        :param plugin_id: 插件标识
        :return: 无返回值
        """
        with self._lock:
            self._gates.pop(plugin_id, None)

    def clear(self) -> None:
        """丢弃全部配额记录。

        :return: 无返回值
        """
        with self._lock:
            self._gates.clear()

    @asynccontextmanager
    async def async_slot(self, plugin_id: str) -> AsyncIterator[bool]:
        """占用插件的一个并发槽位，退出时归还。

        槽位耗尽时按超时等待；等待超时后点名插件记录告警并放行本次调用，因为静默
        丢弃插件任务会造成难以排查的功能缺失。
        :param plugin_id: 插件标识
        :return: 异步上下文管理器，产出本次是否在配额内取得槽位
        """
        semaphore, capacity = self.gate(plugin_id)
        acquired = await self._async_acquire(semaphore, plugin_id, capacity)
        try:
            yield acquired
        finally:
            if acquired:
                semaphore.release()

    async def _async_acquire(
        self,
        semaphore: threading.BoundedSemaphore,
        plugin_id: str,
        capacity: int,
    ) -> bool:
        """在不占用线程的前提下等待一个空闲槽位。

        :param semaphore: 插件的闸门信号量
        :param plugin_id: 插件标识
        :param capacity: 该插件的槽位数
        :return: 是否取得槽位；等待超时返回 False
        """
        if semaphore.acquire(blocking=False):
            return True
        deadline = time.monotonic() + self._wait_timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(self._poll_interval)
            if semaphore.acquire(blocking=False):
                return True
        logger.warn(
            f"插件 {plugin_id} 并发执行数已达配额 {capacity}，"
            f"等待 {self._wait_timeout:.1f} 秒仍无空闲槽位，本次调用不再受配额约束"
        )
        return False

    @contextmanager
    def slot(self, plugin_id: str) -> Iterator[bool]:
        """占用插件的一个并发槽位，退出时归还，语义与 `async_slot` 一致。

        供不在事件循环里的调用方使用，调用线程会被阻塞直至取得槽位或等待超时。
        调用方必须在把任务交给线程池之前取槽，而不是在池 worker 内部取——worker
        内部取会让排队任务占着池线程等待自己的信号量，比不设配额更糟；因此若要
        跨线程使用（取槽线程与释放槽线程不同），需自行驱动
        `__enter__`/`__exit__`，不能用 `with` 包住整个提交加执行过程。
        :param plugin_id: 插件标识
        :return: 同步上下文管理器，产出本次是否在配额内取得槽位
        """
        semaphore, capacity = self.gate(plugin_id)
        acquired = semaphore.acquire(timeout=self._wait_timeout)
        if not acquired:
            logger.warn(
                f"插件 {plugin_id} 并发执行数已达配额 {capacity}，"
                f"等待 {self._wait_timeout:.1f} 秒仍无空闲槽位，本次调用不再受配额约束"
            )
        try:
            yield acquired
        finally:
            if acquired:
                semaphore.release()
