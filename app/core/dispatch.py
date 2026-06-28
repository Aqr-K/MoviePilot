"""
按方法名分发到多后端的共享内核：遍历后端、按合并规则累积结果、隔离单后端的错误与限流。

供 ChainBase（metaclass=ABCMeta）与门面管理器（ManagerBase 系，metaclass=Singleton）以组合委托方式
复用，规避两者元类冲突。内核对转发给后端的 kwargs 内容无主张：是否携带 raise_exception 等控制位由
调用方决定，内核原样 func(*args, **kwargs) 转发。
"""
import inspect
from collections.abc import Callable, Iterable
from typing import Any, Optional, Tuple

from fastapi.concurrency import run_in_threadpool

from app.schemas.exception import RateLimitExceededException
from app.utils.object import ObjectUtils

# 后端三元组：(ident 后端标识, name 显示名, func 待调用方法)
Entry = Tuple[str, str, Callable]


def is_valid_empty(ret: Any) -> bool:
    """判断分发结果是否为空：元组需全部为 None，其余按 is None 判断。"""
    if isinstance(ret, tuple):
        return all(value is None for value in ret)
    return ret is None


def execute_modules(
        entries: Iterable[Entry],
        method: str,
        result: Any,
        *args,
        pipeline: bool,
        on_rate_limit: Callable,
        on_error: Callable,
        log_each: Optional[Callable] = None,
        **kwargs,
) -> Any:
    """
    同步依次遍历后端并按合并规则累积结果。

    合并规则：当前结果为空（None / 全 None 元组）取后端返回值；pipeline 为真且命中 check_signature 时
    把结果作为下一后端入参透传（逐源精化）；为列表时跨后端 extend；为非空标量时短路停止。单个后端异常
    被隔离后继续其余后端，限流安静跳过；回调可在控制位为真时抛出以透传首个异常。

    :param entries: 后端三元组序列 (ident, name, func)
    :param method: 方法名（用于日志与回调）
    :param result: 已累积的结果（首次分发传 None）
    :param pipeline: 为真启用 check_signature 精化分支（系统后端面），为假关闭（插件钩子面）
    :param on_rate_limit: 限流回调 (err, ident, name, method)
    :param on_error: 错误回调 (err, ident, name, method)
    :param log_each: 可选，每个后端调用前触发 (name, method)
    :return: 累积后的结果
    """
    for ident, name, func in entries:
        try:
            if log_each is not None:
                log_each(name, method)
            if is_valid_empty(result):
                result = func(*args, **kwargs)
            elif pipeline and ObjectUtils.check_signature(func, result):
                result = func(result)
            elif isinstance(result, list):
                temp = func(*args, **kwargs)
                if isinstance(temp, list):
                    result.extend(temp)
            else:
                break
        except RateLimitExceededException as err:
            on_rate_limit(err, ident, name, method)
        except Exception as err:
            on_error(err, ident, name, method)
    return result


async def async_execute_modules(
        entries: Iterable[Entry],
        method: str,
        result: Any,
        *args,
        pipeline: bool,
        on_rate_limit: Callable,
        on_error: Callable,
        log_each: Optional[Callable] = None,
        **kwargs,
) -> Any:
    """
    异步依次遍历后端并按合并规则累积结果：同步后端方法经线程池执行避免阻塞事件循环，async 后端直接 await。

    参数、合并规则、错误与限流隔离均同 execute_modules。

    :param entries: 后端三元组序列 (ident, name, func)
    :param method: 方法名（用于日志与回调）
    :param result: 已累积的结果（首次分发传 None）
    :param pipeline: 为真启用 check_signature 精化分支（系统后端面），为假关闭（插件钩子面）
    :param on_rate_limit: 限流回调 (err, ident, name, method)
    :param on_error: 错误回调 (err, ident, name, method)
    :param log_each: 可选，每个后端调用前触发 (name, method)
    :return: 累积后的结果
    """
    for ident, name, func in entries:
        try:
            if log_each is not None:
                log_each(name, method)
            if is_valid_empty(result):
                if inspect.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = await run_in_threadpool(func, *args, **kwargs)
            elif pipeline and ObjectUtils.check_signature(func, result):
                if inspect.iscoroutinefunction(func):
                    result = await func(result)
                else:
                    result = await run_in_threadpool(func, result)
            elif isinstance(result, list):
                if inspect.iscoroutinefunction(func):
                    temp = await func(*args, **kwargs)
                else:
                    temp = await run_in_threadpool(func, *args, **kwargs)
                if isinstance(temp, list):
                    result.extend(temp)
            else:
                break
        except RateLimitExceededException as err:
            on_rate_limit(err, ident, name, method)
        except Exception as err:
            on_error(err, ident, name, method)
    return result
