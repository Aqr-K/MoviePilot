# -*- coding: utf-8 -*-
"""
事件值对象与调度常量（从单文件 app/core/event.py 拆出的轻量数据层）。

注意：此处 models 指事件的值对象 Event 与队列/优先级调优常量，**并非数据库模型**；
仅依赖标准库与 EventType/ChainEventType 枚举，可被只需要 Event 的代码引用而不牵涉管理器逻辑。
"""
import uuid
from typing import Dict, Optional, Union

from app.schemas import ChainEventData
from app.schemas.types import ChainEventType, EventType

DEFAULT_EVENT_PRIORITY = 10  # 事件的默认优先级
MIN_EVENT_CONSUMER_THREADS = 1  # 最小事件消费者线程数
INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS = 1  # 事件队列空闲时的初始超时时间（秒）
MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS = 5  # 事件队列空闲时的最大超时时间（秒）


class Event:
    """
    事件类，封装事件的基本信息
    """

    def __init__(self, event_type: Union[EventType, ChainEventType],
                 event_data: Optional[Union[Dict, ChainEventData]] = None,
                 priority: Optional[int] = DEFAULT_EVENT_PRIORITY):
        """
        :param event_type: 事件的类型，支持 EventType 或 ChainEventType
        :param event_data: 可选，事件携带的数据，默认为空字典
        :param priority: 可选，事件的优先级，默认为 10
        """
        self.event_id = str(uuid.uuid4())  # 事件ID
        self.event_type = event_type  # 事件类型
        self.event_data = event_data or {}  # 事件数据
        self.priority = priority  # 事件优先级

    def __repr__(self) -> str:
        """
        重写 __repr__ 方法，用于返回事件的详细信息，包括事件类型、事件ID和优先级
        """
        event_kind = Event.get_event_kind(self.event_type)
        return f"<{event_kind}: {self.event_type.value}, ID: {self.event_id}, Priority: {self.priority}>"

    def __lt__(self, other):
        """
        定义事件对象的比较规则，基于优先级比较
        优先级小的事件会被认为“更小”，优先级高的事件将被认为“更大”
        """
        return self.priority < other.priority

    @staticmethod
    def get_event_kind(event_type: Union[EventType, ChainEventType]) -> str:
        """
        根据事件类型判断事件是广播事件还是链式事件
        :param event_type: 事件类型，支持 EventType 或 ChainEventType
        :return: 返回 Broadcast Event 或 Chain Event
        """
        return "Broadcast Event" if isinstance(event_type, EventType) else "Chain Event"
