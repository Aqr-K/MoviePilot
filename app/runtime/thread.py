from concurrent.futures import ThreadPoolExecutor

import anyio.to_thread

from app.runtime.config import settings
from app.foundation.singleton import Singleton


def resolve_default_thread_limit() -> int:
    """计算 anyio 默认线程槽上限。

    :return: `API_THREAD_LIMIT` 大于 0 时返回该显式覆盖值，否则返回
        `CONF.threadpool`
    """
    if settings.API_THREAD_LIMIT > 0:
        return settings.API_THREAD_LIMIT
    return settings.CONF.threadpool


def configure_default_thread_limiter() -> None:
    """把 anyio 默认线程槽上限对齐共享线程池容量。

    必须在运行中的事件循环内调用。仅在目标值大于当前值时放大槽位，
    避免在已借出令牌的情况下缩小上限。
    :return: 无返回值
    """
    limiter = anyio.to_thread.current_default_thread_limiter()
    target = resolve_default_thread_limit()
    if target > limiter.total_tokens:
        limiter.total_tokens = target


class ThreadHelper(metaclass=Singleton):
    """
    线程池管理
    """
    def __init__(self):
        """按系统配置创建共享后台线程池。"""
        self.pool = ThreadPoolExecutor(max_workers=settings.CONF.threadpool)

    def submit(self, func, *args, **kwargs):
        """
        提交任务
        :param func: 函数
        :param args: 参数
        :param kwargs: 参数
        :return: future
        """
        return self.pool.submit(func, *args, **kwargs)

    def shutdown(self):
        """
        关闭线程池
        :return:
        """
        self.pool.shutdown()
