import asyncio
import inspect
import random
import threading
import time
import traceback
import uuid
from dataclasses import dataclass
from queue import Empty, PriorityQueue
from typing import Callable, Dict, List, Optional, Tuple, Union, Any, Type

from fastapi.concurrency import run_in_threadpool

from app.runtime.config import global_vars
from app.runtime.extensions.plugin_instance import instance_key, plugin_id_of, split_instance_key
from app.runtime.thread import ThreadHelper
from app.runtime.log import logger
from app.schemas.event import ChainEventData
from app.schemas.types import ChainEventType, EventType
from app.runtime.rate import ExponentialBackoffRateLimiter
from app.foundation.singleton import Singleton

def canonical_target_owner(owner: Optional[str]) -> Optional[str]:
    """
    把定向投递的目标归一成实例键

    裸插件标识与显式写出的默认实例标识都指向默认实例；实例标识非法时原样返回，
    该取值不会等于任何运行中实例的实例键，定向因此落空而不是退化成广播。

    :param owner: 目标插件标识或实例键，为空表示不定向
    :return: 归一后的实例键，为空时返回 None
    """
    if not owner:
        return None
    try:
        return instance_key(*split_instance_key(owner))
    except ValueError:
        return owner


DEFAULT_EVENT_PRIORITY = 10  # 事件的默认优先级
MIN_EVENT_CONSUMER_THREADS = 1  # 最小事件消费者线程数
INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS = 1  # 事件队列空闲时的初始超时时间（秒）
MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS = 5  # 事件队列空闲时的最大超时时间（秒）


@dataclass(frozen=True, slots=True)
class EventHandlerBinding:
    """描述上层运行时为某个事件处理器提供的实例绑定。"""

    instance: Optional[Any]
    owner_name: str
    run_sync_in_threadpool: bool = False
    instance_key: Optional[str] = None


# 实例级禁用条目中处理器类标识与实例键的分隔符
DISABLED_INSTANCE_SEPARATOR = "#"

# 解析器返回该类声明的全部运行实例；类归本解析器管辖但当前无实例时返回空列表，
# 未登记该类时返回 None，交由后续解析器或默认构造兜底
HandlerInstanceResolver = Callable[
    [Type[Any]], Optional[List[EventHandlerBinding]]
]
EventErrorNotifier = Callable[[str, str], object]


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


class EventManager(metaclass=Singleton):
    """
    EventManager 负责管理和调度广播事件和链式事件，包括订阅、发送和处理事件
    """

    def __init__(self):
        """初始化订阅表、处理队列、解析器和消费者状态。"""
        # 动态线程池，用于消费事件
        self.__executor = ThreadHelper()
        # 用于保存启动的事件消费者线程
        self.__consumer_threads = []
        # 优先级队列
        self.__event_queue = PriorityQueue()
        # 广播事件的订阅者
        self.__broadcast_subscribers: Dict[EventType, Dict[str, Callable]] = {}
        # 链式事件的订阅者
        self.__chain_subscribers: Dict[ChainEventType, Dict[str, tuple[int, Callable]]] = {}
        # 禁用的事件处理器集合
        self.__disabled_handlers = set()
        # 整类禁用的事件处理器类集合，覆盖该类的全部实例
        self.__disabled_classes = set()
        # 实例级禁用的事件处理器集合，元素为“类标识#实例键”
        self.__disabled_instances = set()
        # 登记过启停状态的实例键：{类标识: {实例键}}，用于判断某个类是否已无可用实例
        self.__known_instances: Dict[str, set] = {}
        # 线程锁
        self.__lock = threading.Lock()
        # 退出事件
        self.__event = threading.Event()
        # 由上层管理器注册的处理器实例解析器
        self.__handler_instance_resolvers: Dict[str, HandlerInstanceResolver] = {}
        # 由启动组合层注入的错误通知回调
        self.__error_notifier: Optional[EventErrorNotifier] = None

    def register_handler_instance_resolver(
            self,
            name: str,
            resolver: HandlerInstanceResolver,
    ) -> None:
        """
        注册上层运行时的事件处理器实例解析器。

        同名解析器会被替换，避免测试重建单例或热重载后保留旧实例引用。
        """
        with self.__lock:
            self.__handler_instance_resolvers[name] = resolver

    def set_error_notifier(self, notifier: Optional[EventErrorNotifier]) -> None:
        """设置事件处理异常的外部通知回调。"""
        with self.__lock:
            self.__error_notifier = notifier

    def start(self):
        """
        开始广播事件处理线程
        """
        # 启动消费者线程用于处理广播事件
        self.__event.set()
        for _ in range(MIN_EVENT_CONSUMER_THREADS):
            thread = threading.Thread(target=self.__broadcast_consumer_loop, daemon=True)
            thread.start()
            self.__consumer_threads.append(thread)  # 将线程对象保存到列表中

    def stop(self):
        """
        停止广播事件处理线程
        """
        logger.info("正在停止事件处理...")
        self.__event.clear()  # 停止广播事件处理
        try:
            # 通过遍历保存的线程来等待它们完成
            for consumer_thread in self.__consumer_threads:
                consumer_thread.join()
            logger.info("事件处理停止完成")
        except Exception as e:
            logger.error(f"停止事件处理线程出错：{str(e)} - {traceback.format_exc()}")

    def check(self, etype: Union[EventType, ChainEventType]) -> bool:
        """
        检查是否有启用的事件处理器可以响应某个事件类型
        :param etype: 事件类型 (EventType 或 ChainEventType)
        :return: 返回是否存在可用的处理器
        """
        if isinstance(etype, ChainEventType):
            handlers = self.__chain_subscribers.get(etype, {})
            return any(
                self.__is_handler_enabled(handler)
                for _, handler in handlers.values()
            )
        else:
            handlers = self.__broadcast_subscribers.get(etype, {})
            return any(
                self.__is_handler_enabled(handler)
                for handler in handlers.values()
            )

    def send_event(self, etype: Union[EventType, ChainEventType], data: Optional[Union[Dict, ChainEventData]] = None,
                   priority: Optional[int] = DEFAULT_EVENT_PRIORITY) -> Optional[Event]:
        """
        发送事件，根据事件类型决定是广播事件还是链式事件
        :param etype: 事件类型 (EventType 或 ChainEventType)
        :param data: 可选，事件数据
        :param priority: 广播事件的优先级，默认为 10
        :return: 如果是链式事件，返回处理后的事件数据；否则返回 None
        """
        event = Event(etype, data, priority)
        if isinstance(etype, EventType):
            return self.__trigger_broadcast_event(event)
        elif isinstance(etype, ChainEventType):
            return self.__trigger_chain_event(event)
        else:
            logger.error(f"Unknown event type: {etype}")
        return None

    async def async_send_event(self, etype: Union[EventType, ChainEventType],
                               data: Optional[Union[Dict, ChainEventData]] = None,
                               priority: Optional[int] = DEFAULT_EVENT_PRIORITY) -> Optional[Event]:
        """
        异步发送事件，根据事件类型决定是广播事件还是链式事件
        :param etype: 事件类型 (EventType 或 ChainEventType)
        :param data: 可选，事件数据
        :param priority: 广播事件的优先级，默认为 10
        :return: 如果是链式事件，返回处理后的事件数据；否则返回 None
        """
        event = Event(etype, data, priority)
        if isinstance(etype, EventType):
            return self.__trigger_broadcast_event(event)
        elif isinstance(etype, ChainEventType):
            return await self.__trigger_chain_event_async(event)
        else:
            logger.error(f"Unknown event type: {etype}")
        return None

    def add_event_listener(self, event_type: Union[EventType, ChainEventType], handler: Callable,
                           priority: Optional[int] = DEFAULT_EVENT_PRIORITY):
        """
        注册事件处理器，将处理器添加到对应的事件订阅列表中
        :param event_type: 事件类型 (EventType 或 ChainEventType)
        :param handler: 处理器
        :param priority: 可选，链式事件的优先级，默认为 10；广播事件不需要优先级
        """
        with self.__lock:
            handler_identifier = self.__get_handler_identifier(handler)

            if isinstance(event_type, ChainEventType):
                # 链式事件，按优先级排序
                if event_type not in self.__chain_subscribers:
                    self.__chain_subscribers[event_type] = {}
                handlers = self.__chain_subscribers[event_type]
                if handler_identifier in handlers:
                    handlers.pop(handler_identifier)
                else:
                    logger.debug(
                        f"Subscribed to chain event: {event_type.value}, "
                        f"Priority: {priority} - {handler_identifier}")
                handlers[handler_identifier] = (priority, handler)
                # 根据优先级排序
                self.__chain_subscribers[event_type] = dict(
                    sorted(self.__chain_subscribers[event_type].items(), key=lambda x: x[1][0])
                )
            else:
                # 广播事件
                if event_type not in self.__broadcast_subscribers:
                    self.__broadcast_subscribers[event_type] = {}
                handlers = self.__broadcast_subscribers[event_type]
                if handler_identifier in handlers:
                    handlers.pop(handler_identifier)
                else:
                    logger.debug(f"Subscribed to broadcast event: {event_type.value} - {handler_identifier}")
                handlers[handler_identifier] = handler

    def remove_event_listener(self, event_type: Union[EventType, ChainEventType], handler: Callable):
        """
        移除事件处理器，将处理器从对应事件的订阅列表中删除
        :param event_type: 事件类型 (EventType 或 ChainEventType)
        :param handler: 要移除的处理器
        """
        with self.__lock:
            handler_identifier = self.__get_handler_identifier(handler)

            if isinstance(event_type, ChainEventType) and event_type in self.__chain_subscribers:
                self.__chain_subscribers[event_type].pop(handler_identifier, None)
                logger.debug(f"Unsubscribed from chain event: {event_type.value} - {handler_identifier}")
            elif event_type in self.__broadcast_subscribers:
                self.__broadcast_subscribers[event_type].pop(handler_identifier, None)
                logger.debug(f"Unsubscribed from broadcast event: {event_type.value} - {handler_identifier}")

    def disable_event_handler(self, target: Union[Callable, type],
                              instance_key: Optional[str] = None):
        """
        禁用指定的事件处理器或事件处理器类
        :param target: 处理器函数或类
        :param instance_key: 实例键，仅对处理器类有效；为空时禁用该类的全部实例
        """
        identifier = self.__get_handler_identifier(target)
        if not isinstance(target, type):
            if identifier in self.__disabled_handlers:
                return
            self.__disabled_handlers.add(identifier)
            logger.debug(f"Disabled event handler - {identifier}")
            return
        if instance_key is None:
            if identifier in self.__disabled_classes:
                return
            self.__disabled_classes.add(identifier)
            logger.debug(f"Disabled event handler class - {identifier}")
            return
        instance_identifier = self.__disabled_instance_id(identifier, instance_key)
        self.__known_instances.setdefault(identifier, set()).add(instance_key)
        self.__disabled_instances.add(instance_identifier)
        logger.debug(f"Disabled event handler instance - {instance_identifier}")

    def enable_event_handler(self, target: Union[Callable, type],
                             instance_key: Optional[str] = None):
        """
        启用指定的事件处理器或事件处理器类
        :param target: 处理器函数或类
        :param instance_key: 实例键，仅对处理器类有效；为空时启用该类的全部实例
        """
        identifier = self.__get_handler_identifier(target)
        if not isinstance(target, type):
            self.__disabled_handlers.discard(identifier)
            logger.debug(f"Enabled event handler - {identifier}")
            return
        if instance_key is None:
            self.__disabled_classes.discard(identifier)
            logger.debug(f"Enabled event handler class - {identifier}")
            return
        instance_identifier = self.__disabled_instance_id(identifier, instance_key)
        self.__known_instances.setdefault(identifier, set()).add(instance_key)
        self.__disabled_instances.discard(instance_identifier)
        logger.debug(f"Enabled event handler instance - {instance_identifier}")

    @staticmethod
    def __disabled_instance_id(class_identifier: str, instance_key: str) -> str:
        """
        组合实例级禁用条目的标识
        :param class_identifier: 处理器类的唯一标识
        :param instance_key: 实例键
        :return: 实例级禁用条目标识
        """
        return f"{class_identifier}{DISABLED_INSTANCE_SEPARATOR}{instance_key}"

    def visualize_handlers(self) -> List[Dict]:
        """
        可视化所有事件处理器，包括是否被禁用的状态
        :return: 处理器列表，包含事件类型、处理器标识符、优先级（如果有）和状态
        """

        def parse_handler_data(data):
            """
            解析处理器数据，判断是否包含优先级
            :param data: 订阅者数据，可能是元组或单一值
            :return: (priority, handler)，若没有优先级则返回 (None, handler)
            """
            if isinstance(data, tuple) and len(data) == 2:
                return data
            return None, data

        handler_info = []
        # 统一处理广播事件和链式事件
        for event_type, subscribers in {**self.__broadcast_subscribers, **self.__chain_subscribers}.items():
            for handler_identifier, handler_data in subscribers.items():
                # 解析优先级和处理器
                priority, handler = parse_handler_data(handler_data)
                # 检查处理器的启用状态
                status = "enabled" if self.__is_handler_enabled(handler) else "disabled"
                # 构建处理器信息字典
                handler_dict = {
                    "event_type": event_type.value,
                    "handler_identifier": handler_identifier,
                    "status": status
                }
                if priority is not None:
                    handler_dict["priority"] = priority
                handler_info.append(handler_dict)
        return handler_info

    @classmethod
    def __get_handler_identifier(cls, target: Union[Callable, type]) -> Optional[str]:
        """
        获取处理器或处理器类的唯一标识符，包括模块名和类名/方法名
        :param target: 处理器函数或类
        :return: 唯一标识符
        """
        # 统一使用 inspect.getmodule 来获取模块名
        module = inspect.getmodule(target)
        module_name = module.__name__ if module else "unknown_module"

        # 使用 __qualname__ 获取目标的限定名
        qualname = target.__qualname__
        return f"{module_name}.{qualname}"

    @classmethod
    def __get_class_from_callable(cls, handler: Callable) -> Optional[str]:
        """
        获取可调用对象所属类的唯一标识符
        :param handler: 可调用对象（函数、方法等）
        :return: 类的唯一标识符
        """
        # 对于绑定方法，通过 __self__.__class__ 获取类
        if inspect.ismethod(handler) and hasattr(handler, "__self__"):
            return cls.__get_handler_identifier(handler.__self__.__class__)

        # 对于类实例（实现了 __call__ 方法）
        if not inspect.isfunction(handler) and hasattr(handler, "__call__"):
            handler_cls = handler.__class__  # noqa
            return cls.__get_handler_identifier(handler_cls)

        # 对于未绑定方法、静态方法、类方法，使用 __qualname__ 提取类信息
        qualname_parts = handler.__qualname__.split(".")
        if len(qualname_parts) > 1:
            class_name = ".".join(qualname_parts[:-1])
            module = inspect.getmodule(handler)
            module_name = module.__name__ if module else "unknown_module"
            return f"{module_name}.{class_name}"
        return None

    def __is_handler_enabled(self, handler: Callable) -> bool:
        """
        检查处理器是否还有可投递的实例
        :param handler: 处理器函数
        :return: 处理器自身未被禁用且所属类至少有一个启用实例时返回 True
        """
        # 获取处理器的唯一标识符
        handler_id = self.__get_handler_identifier(handler)
        if handler_id in self.__disabled_handlers:
            return False

        # 获取处理器所属类的唯一标识符
        return self.__is_class_enabled(self.__get_class_from_callable(handler))

    def __is_class_enabled(self, class_identifier: Optional[str]) -> bool:
        """
        检查处理器类是否至少有一个启用的实例
        :param class_identifier: 处理器类的唯一标识
        :return: 是否存在可投递的实例
        """
        if class_identifier is None:
            return True
        if class_identifier in self.__disabled_classes:
            return False
        known = self.__known_instances.get(class_identifier)
        if not known:
            return True
        return any(
            self.__disabled_instance_id(class_identifier, instance_key) not in self.__disabled_instances
            for instance_key in known
        )

    def __is_instance_enabled(self, class_identifier: Optional[str],
                              instance_key: Optional[str]) -> bool:
        """
        检查处理器类的某个实例是否已启用
        :param class_identifier: 处理器类的唯一标识
        :param instance_key: 实例键，为空时只做类级判定
        :return: 是否可以向该实例投递
        """
        if class_identifier is None:
            return True
        if class_identifier in self.__disabled_classes:
            return False
        if instance_key is None:
            return True
        return self.__disabled_instance_id(class_identifier, instance_key) not in self.__disabled_instances

    def __trigger_chain_event(self, event: Event) -> Optional[Event]:
        """
        触发链式事件，按顺序调用订阅的处理器，并记录处理耗时
        """
        logger.debug(f"Triggering synchronous chain event: {event}")
        dispatch = self.__dispatch_chain_event(event)
        return event if dispatch else None

    async def __trigger_chain_event_async(self, event: Event) -> Optional[Event]:
        """
        异步触发链式事件，按顺序调用订阅的处理器，并记录处理耗时
        """
        logger.debug(f"Triggering asynchronous chain event: {event}")
        dispatch = await self.__dispatch_chain_event_async(event)
        return event if dispatch else None

    def __trigger_broadcast_event(self, event: Event):
        """
        触发广播事件，将事件插入到优先级队列中
        :param event: 要处理的事件对象
        """
        logger.debug(f"Triggering broadcast event: {event}")
        self.__event_queue.put((event.priority, event))

    def __dispatch_chain_event(self, event: Event) -> bool:
        """
        同步方式调度链式事件，按优先级顺序逐个调用事件处理器，并记录每个处理器的处理时间
        :param event: 要调度的事件对象
        """
        # 运行期可以动态注册或移除处理器；当前事件始终使用调度开始时的快照。
        with self.__lock:
            handlers = tuple(
                self.__chain_subscribers.get(event.event_type, {}).items()
            )
        if not handlers:
            logger.debug(f"No handlers found for chain event: {event}")
            return False

        # 过滤出启用的处理器
        enabled_handlers = tuple(
            (handler_id, priority, handler)
            for handler_id, (priority, handler) in handlers
            if self.__is_handler_enabled(handler)
        )

        if not enabled_handlers:
            logger.debug(f"No enabled handlers found for chain event: {event}. Skipping execution.")
            return False

        self.__log_event_lifecycle(event, "Started")
        for handler_id, priority, handler in enabled_handlers:
            start_time = time.time()
            self.__safe_invoke_handler(handler, event)
            logger.debug(
                f"{self.__get_handler_identifier(handler)} (Priority: {priority}), "
                f"completed in {time.time() - start_time:.3f}s for event: {event}"
            )
        self.__log_event_lifecycle(event, "Completed")
        return True

    async def __dispatch_chain_event_async(self, event: Event) -> bool:
        """
        异步方式调度链式事件，按优先级顺序逐个调用事件处理器，并记录每个处理器的处理时间
        :param event: 要调度的事件对象
        """
        # 快照在锁内建立、在锁外执行，处理器可以安全地修改后续订阅。
        with self.__lock:
            handlers = tuple(
                self.__chain_subscribers.get(event.event_type, {}).items()
            )
        if not handlers:
            logger.debug(f"No handlers found for chain event: {event}")
            return False

        # 过滤出启用的处理器
        enabled_handlers = tuple(
            (handler_id, priority, handler)
            for handler_id, (priority, handler) in handlers
            if self.__is_handler_enabled(handler)
        )

        if not enabled_handlers:
            logger.debug(f"No enabled handlers found for chain event: {event}. Skipping execution.")
            return False

        self.__log_event_lifecycle(event, "Started")
        for handler_id, priority, handler in enabled_handlers:
            start_time = time.time()
            await self.__safe_invoke_handler_async(handler, event)
            logger.debug(
                f"{self.__get_handler_identifier(handler)} (Priority: {priority}), "
                f"completed in {time.time() - start_time:.3f}s for event: {event}"
            )
        self.__log_event_lifecycle(event, "Completed")
        return True

    def __dispatch_broadcast_event(self, event: Event):
        """
        异步方式调度广播事件，通过线程池逐个调用事件处理器
        :param event: 要调度的事件对象
        """
        # 快照隔离当前调度与运行期订阅变更；变更从下一个事件开始生效。
        with self.__lock:
            handlers = tuple(
                self.__broadcast_subscribers.get(event.event_type, {}).items()
            )
        if not handlers:
            logger.debug(f"No handlers found for broadcast event: {event}")
            return
        target_owner = None
        if event.event_type == EventType.MessageAction and isinstance(event.event_data, dict):
            target_plugin_id = event.event_data.get("__mp_target_plugin_id")
            target_owner = canonical_target_owner(
                str(target_plugin_id) if target_plugin_id else None
            )
        # 为每个处理器提供独立的事件实例，防止某个处理器对 event_data 的修改影响其他处理器
        for handler_id, handler in handlers:
            if target_owner and not self.__should_dispatch_to_target_plugin(
                    handler, handler_id, target_owner
            ):
                continue
            # 仅浅拷贝顶层字典，避免不必要的深拷贝开销；这样可以隔离键级别的替换/赋值
            if isinstance(event.event_data, dict):
                event_data_copy = event.event_data.copy()
                event_data_copy.pop("__mp_target_plugin_id", None)
            else:
                event_data_copy = event.event_data
            isolated_event = Event(event_type=event.event_type,
                                   event_data=event_data_copy,
                                   priority=event.priority)
            if inspect.iscoroutinefunction(handler):
                # 对于异步函数，直接在事件循环中运行
                asyncio.run_coroutine_threadsafe(
                    self.__safe_invoke_handler_async(handler, isolated_event, True, target_owner),
                    global_vars.loop
                )
            else:
                # 对于同步函数，在线程池中运行
                self.__executor.submit(
                    self.__safe_invoke_handler, handler, isolated_event, True, target_owner
                )

    @classmethod
    def __should_dispatch_to_target_plugin(
            cls,
            handler: Callable,
            handler_identifier: str,
            target_plugin_id: str,
    ) -> bool:
        """
        限定插件输入事件只投递给目标插件，避免自由文本被其他插件观察到。

        :param handler: 处理器
        :param handler_identifier: 处理器的唯一标识
        :param target_plugin_id: 目标插件标识或实例键
        :return: 该处理器所属的类是否为目标插件
        """
        class_name, method_name = cls.__parse_handler_names(handler)
        if class_name != plugin_id_of(target_plugin_id):
            return False
        identifier_parts = (handler_identifier or "").split(".")
        if len(identifier_parts) < 2:
            logger.debug(
                "Target plugin dispatch skipped because handler identifier is invalid: "
                f"target={target_plugin_id}, handler={handler_identifier}"
            )
            return False
        if identifier_parts[-2:] != [class_name, method_name]:
            logger.debug(
                "Target plugin dispatch skipped because handler identifier does not match handler: "
                f"target={target_plugin_id}, handler={handler_identifier}, parsed={class_name}.{method_name}"
            )
            return False
        return True

    def __safe_invoke_handler(self, handler: Callable, event: Event, isolate: bool = False,
                              target_owner: Optional[str] = None):
        """
        调用处理器，处理链式或广播事件
        :param handler: 处理器
        :param event: 事件对象
        :param isolate: 是否为处理器的每个实例提供独立的事件对象
        :param target_owner: 定向投递的插件标识或实例键，为空时投递给全部启用实例
        """
        if not self.__is_handler_enabled(handler):
            logger.debug(f"Handler {self.__get_handler_identifier(handler)} is disabled. Skipping execution")
            return

        self.__invoke_handler_by_type_sync(handler, event, isolate, target_owner)

    async def __safe_invoke_handler_async(self, handler: Callable, event: Event, isolate: bool = False,
                                          target_owner: Optional[str] = None):
        """
        异步调用处理器，处理链式事件
        :param handler: 处理器
        :param event: 事件对象
        :param isolate: 是否为处理器的每个实例提供独立的事件对象
        :param target_owner: 定向投递的插件标识或实例键，为空时投递给全部启用实例
        """
        if not self.__is_handler_enabled(handler):
            logger.debug(f"Handler {self.__get_handler_identifier(handler)} is disabled. Skipping execution")
            return

        await self.__invoke_handler_by_type_async(handler, event, isolate, target_owner)

    def __invoke_handler_by_type_sync(self, handler: Callable, event: Event, isolate: bool = False,
                                      target_owner: Optional[str] = None):
        """
        同步方式在处理器的全部启用实例上调用相应的方法
        :param handler: 处理器
        :param event: 要处理的事件对象
        :param isolate: 是否为处理器的每个实例提供独立的事件对象
        :param target_owner: 定向投递的插件标识或实例键，为空时投递给全部启用实例
        """
        for index, (method, binding, class_name, method_name) in enumerate(
                self.__resolve_handler(handler, target_owner)):
            target_event = event if index == 0 or not isolate else self.__isolate_event(event)
            try:
                method(target_event)
            except Exception as e:
                self.__handle_event_error(
                    event=target_event,
                    module_name=binding.owner_name,
                    class_name=class_name,
                    method_name=method_name,
                    e=e,
                )

    async def __invoke_handler_by_type_async(self, handler: Callable, event: Event, isolate: bool = False,
                                             target_owner: Optional[str] = None):
        """
        异步方式在处理器的全部启用实例上调用相应的方法
        :param handler: 处理器
        :param event: 要处理的事件对象
        :param isolate: 是否为处理器的每个实例提供独立的事件对象
        :param target_owner: 定向投递的插件标识或实例键，为空时投递给全部启用实例
        """
        for index, (method, binding, class_name, method_name) in enumerate(
                self.__resolve_handler(handler, target_owner)):
            target_event = event if index == 0 or not isolate else self.__isolate_event(event)
            try:
                if inspect.iscoroutinefunction(method):
                    await method(target_event)
                elif binding.run_sync_in_threadpool or not class_name:
                    await run_in_threadpool(method, target_event)
                else:
                    method(target_event)
            except Exception as e:
                self.__handle_event_error(
                    event=target_event,
                    module_name=binding.owner_name,
                    class_name=class_name,
                    method_name=method_name,
                    e=e,
                )

    @staticmethod
    def __parse_handler_names(handler: Callable) -> Tuple[str, str]:
        """
        解析处理器的类名和方法名
        :param handler: 处理器
        :return: (class_name, method_name)
        """
        names = handler.__qualname__.split(".")
        if len(names) < 2:
            return "", names[0]
        return names[0], names[1]

    @staticmethod
    def __get_handler_owner_class(handler: Callable) -> Optional[Type[Any]]:
        """从处理器对象本身解析声明它的类，不按命名约定动态导入模块。"""
        if inspect.ismethod(handler):
            owner = handler.__self__
            return owner if isinstance(owner, type) else type(owner)
        module = inspect.getmodule(handler)
        if not module:
            return None
        owner: Any = module
        for part in handler.__qualname__.split(".")[:-1]:
            if part == "<locals>":
                return None
            owner = getattr(owner, part, None)
            if owner is None:
                return None
        return owner if isinstance(owner, type) else None

    def __resolve_handler(
            self,
            handler: Callable,
            target_owner: Optional[str] = None,
    ) -> List[Tuple[Callable, EventHandlerBinding, str, str]]:
        """将装饰阶段保存的函数解析为当前全部启用实例上的可调用方法。

        :param handler: 装饰阶段保存的处理器函数
        :param target_owner: 定向投递的目标，只命中实例键与之相等的那一个实例；
            裸插件标识即默认实例的实例键，为空时不做定向筛选
        :return: (方法, 实例绑定, 类名, 方法名) 列表
        """
        target_owner = canonical_target_owner(target_owner)
        owner_class = self.__get_handler_owner_class(handler)
        method_name = getattr(handler, "__name__", self.__parse_handler_names(handler)[1])
        if owner_class is None:
            binding = EventHandlerBinding(
                instance=None,
                owner_name=self.__get_handler_identifier(handler),
                run_sync_in_threadpool=True,
            )
            return [(handler, binding, "", method_name)]

        with self.__lock:
            resolvers = list(self.__handler_instance_resolvers.values())
        bindings = next(
            (result for resolver in resolvers if (result := resolver(owner_class)) is not None),
            None,
        )
        if bindings is None:
            try:
                get_existing = getattr(owner_class, "get_existing_instance", None)
                instance = get_existing() if callable(get_existing) else None
                if instance is None:
                    instance = owner_class()
                bindings = [EventHandlerBinding(
                    instance=instance,
                    owner_name=owner_class.__name__,
                )]
            except Exception as e:
                logger.error(
                    f"事件处理出错：创建 {owner_class.__name__} 实例失败："
                    f"{str(e)} - {traceback.format_exc()}"
                )
                return []
        class_identifier = self.__get_handler_identifier(owner_class)
        resolved = []
        for binding in bindings:
            if binding.instance is None:
                continue
            if not self.__is_instance_enabled(class_identifier, binding.instance_key):
                continue
            # 定向投递的事件携带用户自由文本，只能交给会话所属的那一个实例；
            # 未登记实例键的绑定只有一个实例，按默认实例参与比对
            if target_owner and (binding.instance_key or owner_class.__name__) != target_owner:
                continue
            resolved_name = method_name
            method = getattr(binding.instance, resolved_name, None)
            if not callable(method):
                # 动态生成的处理器可能只同步了 __qualname__，__name__ 与类上方法名不一致时
                # 回退到限定名末段重试；仍无法解析时记录告警，避免静默跳过
                fallback_name = self.__parse_handler_names(handler)[1]
                method = getattr(binding.instance, fallback_name, None)
                if fallback_name == resolved_name or not callable(method):
                    logger.warning(
                        f"事件处理器 {self.__get_handler_identifier(handler)} "
                        f"无法解析为实例方法 {owner_class.__name__}.{resolved_name}，跳过执行"
                    )
                    continue
                resolved_name = fallback_name
            resolved.append((method, binding, owner_class.__name__, resolved_name))
        return resolved

    def __broadcast_consumer_loop(self):
        """
        持续从队列中提取事件的后台广播消费者线程
        """
        jitter_factor = 0.1
        rate_limiter = ExponentialBackoffRateLimiter(base_wait=INITIAL_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS,
                                                     max_wait=MAX_EVENT_QUEUE_IDLE_TIMEOUT_SECONDS,
                                                     backoff_factor=2.0,
                                                     source="BroadcastConsumer",
                                                     enable_logging=False)
        while self.__event.is_set():
            try:
                priority, event = self.__event_queue.get(timeout=rate_limiter.current_wait)
                rate_limiter.reset()
                self.__dispatch_broadcast_event(event)
            except Empty:
                rate_limiter.current_wait = rate_limiter.current_wait * random.uniform(1, 1 + jitter_factor)
                rate_limiter.trigger_limit()

    @staticmethod
    def __log_event_lifecycle(event: Event, stage: str):
        """
        记录事件的生命周期日志
        """
        logger.debug(f"{stage} - {event}")

    def __handle_event_error(self, event: Event, module_name: str,
                             class_name: str, method_name: str, e: Exception):
        """
        全局错误处理器，用于处理事件处理中的异常
        """
        logger.error(f"{module_name} 事件处理出错：{str(e)} - {traceback.format_exc()}")

        # 消息实现由启动组合层注入，事件总线不反向依赖消息模块。
        with self.__lock:
            notifier = self.__error_notifier
        if notifier:
            try:
                notifier(
                    f"{module_name} 处理事件 {event.event_type} 时出错",
                    f"{class_name}.{method_name}：{str(e)}",
                )
            except Exception as notify_error:
                logger.error(f"发送事件错误通知失败：{str(notify_error)}")
        self.send_event(
            EventType.SystemError,
            {
                "type": "event",
                "event_type": event.event_type,
                "event_handle": f"{class_name}.{method_name}",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        )

    def register(self, etype: Union[EventType, ChainEventType, List[Union[EventType, ChainEventType]], type],
                 priority: Optional[int] = DEFAULT_EVENT_PRIORITY):
        """
        事件注册装饰器，用于将函数注册为事件的处理器
        :param etype:
            - 单个事件类型成员 (如 EventType.MetadataScrape, ChainEventType.PluginAction)
            - 事件类型类 (EventType, ChainEventType)
            - 或事件类型成员的列表
        :param priority: 可选，链式事件的优先级，默认为 DEFAULT_EVENT_PRIORITY
        """

        def decorator(f: Callable):
            # 将输入的事件类型统一转换为列表格式
            if isinstance(etype, list):
                # 传入的已经是列表，直接使用
                event_list = etype
            else:
                # 不是列表则包裹成单一元素的列表
                event_list = [etype]

            # 遍历列表，处理每个事件类型
            for event in event_list:
                if isinstance(event, (EventType, ChainEventType)):
                    self.add_event_listener(event, f, priority)
                elif isinstance(event, type) and issubclass(event, (EventType, ChainEventType)):
                    # 如果是 EventType 或 ChainEventType 类，提取该类中的所有成员
                    for et in event.__members__.values():
                        self.add_event_listener(et, f, priority)
                else:
                    raise ValueError(f"无效的事件类型: {event}")

            return f

        return decorator


# 模块热重载时类对象会重新创建，但插件和 SDK 可能仍持有旧全局实例。把旧实例登记到
# 新 EventManager 类的单例键，确保所有公开入口继续共享同一个事件总线。
_existing_eventmanager = globals().get("eventmanager")
if _existing_eventmanager is not None:
    Singleton._instances[(EventManager, (), frozenset())] = _existing_eventmanager
# 全局实例定义
eventmanager = EventManager()
