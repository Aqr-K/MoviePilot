# -*- coding: utf-8 -*-
"""
app.core.event 包：事件值对象（models）+ 事件管理器（manager）。

稳定公共 API（保持 from app.core.event import X 零改动；历史为单文件 app/core/event.py）：
  - Event         事件值对象，见 .models
  - EventManager  事件管理器（订阅/广播/链式调度），见 .manager
  - eventmanager  EventManager 全局单例
  - DEFAULT_EVENT_PRIORITY / MIN_EVENT_CONSUMER_THREADS /
    INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS / MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS  调度常量

采用**急切再导出**（非懒加载）：历史单文件在 import 期即构造全局单例 eventmanager，
且不存在「需独立轻量 import 某子模块」的不变量（与 app.core.module 的 loader 不同），
故此处直接再导出，保持导入行为与单例构造时机与历史完全一致。
"""
from app.core.event.models import (
    Event,
    DEFAULT_EVENT_PRIORITY,
    MIN_EVENT_CONSUMER_THREADS,
    INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS,
    MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS,
)
from app.core.event.manager import EventManager, eventmanager

__all__ = [
    "Event",
    "EventManager",
    "eventmanager",
    "DEFAULT_EVENT_PRIORITY",
    "MIN_EVENT_CONSUMER_THREADS",
    "INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS",
    "MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS",
]
