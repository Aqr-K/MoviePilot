"""事件循环阻塞检测：判定当前是否运行在事件循环线程，并从调用栈归因到插件。

只做栈帧静态归因和独立线程采样，不 monkey-patch 标准库阻塞调用（如 `open`/`socket`）。
理由见 `docs/process-isolation-design.md` 附随报告：本项目插件可自由安装第三方
C 扩展依赖，覆盖面无法穷举且落到 C 层的阻塞（如已在读写中的文件句柄、SSL 握手）
包不住；侵入式补丁一旦与 asyncio/uvloop 自身对同一批标准库对象的使用冲突，
风险高于收益。改用对现有阻塞面无侵入的独立线程栈采样，配合延迟探针即可回答
「事件循环被阻塞时栈里有没有插件代码、是哪个插件」这一核心问题。
"""

from __future__ import annotations

import sys
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.runtime.config import settings

_PLUGINS_PACKAGE_PARTS = ("app", "plugins")


@dataclass(frozen=True, slots=True)
class PluginStackAttribution:
    """从调用栈定位出的插件归因结果。"""

    plugin_id: str
    file: str
    line: int
    function: str


def _plugin_id_from_file_path(file_path: str) -> Optional[str]:
    """从帧的文件路径解析插件 ID：路径中 app/plugins 之后的下一段即插件 ID。

    兼容存量布局 `app/plugins/<pid>/xxx.py` 与按版本分目录布局
    `app/plugins/<pid>/<版本号>/xxx.py`，两种布局插件 ID 都是 app/plugins 之后的第一段。
    """
    try:
        parts = Path(file_path).parts
    except (TypeError, ValueError):
        return None
    limit = len(parts) - len(_PLUGINS_PACKAGE_PARTS)
    for index in range(limit):
        if tuple(parts[index:index + 2]) == _PLUGINS_PACKAGE_PARTS:
            remaining = parts[index + 2:]
            return remaining[0] if remaining else None
    return None


def attribute_plugin_from_stack(
    frame_summaries: list[traceback.FrameSummary],
) -> Optional[PluginStackAttribution]:
    """从调用栈中定位最内层（最贴近阻塞点）的插件代码帧。

    :param frame_summaries: 待扫描的栈帧序列，顺序为最外层调用方在前、当前帧在后
    :return: 命中的插件归因信息，未发现插件代码时返回 None
    """
    for summary in reversed(frame_summaries):
        plugin_id = _plugin_id_from_file_path(summary.filename)
        if plugin_id:
            return PluginStackAttribution(
                plugin_id=plugin_id,
                file=summary.filename,
                line=summary.lineno or 0,
                function=summary.name,
            )
    return None


def attribute_plugin_from_frame(frame) -> Optional[PluginStackAttribution]:
    """沿帧链向外回溯，定位最内层（最贴近阻塞点）的插件代码帧。

    直接读取帧的代码对象，不经 `traceback.extract_stack`：后者会为栈中每个文件
    调用 `linecache.checkcache` 触发 `os.stat` 并读取源码行，而归因只需要文件名、
    行号与函数名。采样以固定频率常驻运行，这笔开销会按栈深放大成常驻负担。

    :param frame: 起始帧，通常是目标线程当前正在执行的帧，可为 None
    :return: 命中的插件归因信息，未发现插件代码时返回 None
    """
    current = frame
    while current is not None:
        filename = current.f_code.co_filename
        plugin_id = _plugin_id_from_file_path(filename)
        if plugin_id:
            return PluginStackAttribution(
                plugin_id=plugin_id,
                file=filename,
                line=current.f_lineno,
                function=current.f_code.co_name,
            )
        current = current.f_back
    return None


def attribute_plugin_from_thread_frame(thread_ident: int) -> Optional[PluginStackAttribution]:
    """从指定线程当前挂起的 Python 帧向上回溯，定位插件代码帧。

    :param thread_ident: 目标线程的 `threading.get_ident()` 值
    :return: 命中的插件归因信息，取不到帧或未发现插件代码时返回 None
    """
    return attribute_plugin_from_frame(sys._current_frames().get(thread_ident))


_event_loop_thread_ident: Optional[int] = None


def record_event_loop_thread() -> None:
    """记录当前线程为事件循环所在线程，供 `is_running_in_event_loop_thread` 判定使用。"""
    global _event_loop_thread_ident
    _event_loop_thread_ident = threading.get_ident()


def is_running_in_event_loop_thread() -> bool:
    """判断当前线程是否就是 `record_event_loop_thread` 记录的事件循环线程。"""
    return (
        _event_loop_thread_ident is not None
        and threading.get_ident() == _event_loop_thread_ident
    )


class EventLoopBlockingWatchdog:
    """独立操作系统线程周期性采样目标线程当前帧，尝试从中归因插件代码。

    与延迟探针配合定位「插件拖垮应用」的真实原因：延迟探针本身运行在事件循环上，
    只能在阻塞结束、控制权交还后才被唤醒，看不到阻塞发生时的栈；本采样器运行在
    独立线程，能在事件循环线程仍被同步代码占用期间取到其当时的真实调用栈。
    """

    def __init__(self, *, sample_interval_seconds: float, history_size: int = 64) -> None:
        """
        :param sample_interval_seconds: 采样周期（秒）
        :param history_size: 保留的历史采样条数
        """
        self._sample_interval_seconds = sample_interval_seconds
        self._loop_thread_ident: Optional[int] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._history: deque[tuple[float, Optional[PluginStackAttribution]]] = deque(
            maxlen=history_size
        )

    def start(self, loop_thread_ident: int) -> None:
        """记录被观测线程并启动采样线程，重复调用是幂等的。"""
        self._loop_thread_ident = loop_thread_ident
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="mp-loop-blocking-watchdog",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """停止采样线程并等待其退出，重复调用是幂等的。"""
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop_event.wait(self._sample_interval_seconds):
            self._sample()

    def _sample(self) -> None:
        """采样一次目标线程当前帧并记入历史，未命中插件代码也记录空结果以标注采样时刻。"""
        if self._loop_thread_ident is None:
            return
        attribution = attribute_plugin_from_frame(
            sys._current_frames().get(self._loop_thread_ident)
        )
        with self._lock:
            self._history.append((time.monotonic(), attribution))

    def last_plugin_attribution(self) -> Optional[PluginStackAttribution]:
        """返回历史采样中最近一次命中插件代码的归因，未命中过时返回 None。"""
        with self._lock:
            for _, attribution in reversed(self._history):
                if attribution is not None:
                    return attribution
        return None

    def attribution_since(self, since_monotonic: float) -> Optional[PluginStackAttribution]:
        """返回指定时间点之后最近一次命中插件代码的归因，早于该时间点的历史命中忽略不计。

        :param since_monotonic: `time.monotonic()` 时间基准下的起始时间点
        """
        with self._lock:
            for sampled_at, attribution in reversed(self._history):
                if sampled_at < since_monotonic:
                    break
                if attribution is not None:
                    return attribution
        return None

    def clear(self) -> None:
        """清空已记录的历史采样，供测试或诊断重置基线使用。"""
        with self._lock:
            self._history.clear()


_watchdog: Optional[EventLoopBlockingWatchdog] = None


def get_event_loop_blocking_watchdog() -> Optional[EventLoopBlockingWatchdog]:
    """返回当前进程内的阻塞检测采样线程实例，未启动时为 None。"""
    return _watchdog


def start_event_loop_blocking_watchdog() -> Optional[EventLoopBlockingWatchdog]:
    """记录当前线程为事件循环线程，并按配置启动阻塞检测采样线程。

    必须在事件循环线程内调用，用于取得正确的被观测线程 ID。

    :return: 采样线程实例；`LOOP_BLOCKING_DETECTOR_ENABLE` 关闭时返回 None 且不创建实例
    """
    global _watchdog
    record_event_loop_thread()
    if not settings.LOOP_BLOCKING_DETECTOR_ENABLE:
        _watchdog = None
        return None
    if _watchdog is None:
        _watchdog = EventLoopBlockingWatchdog(
            sample_interval_seconds=settings.LOOP_BLOCKING_DETECTOR_SAMPLE_INTERVAL_SECONDS,
        )
    _watchdog.start(threading.get_ident())
    return _watchdog


def stop_event_loop_blocking_watchdog() -> None:
    """停止阻塞检测采样线程并清空进程内实例引用。"""
    global _watchdog
    watchdog, _watchdog = _watchdog, None
    if watchdog is not None:
        watchdog.stop()
