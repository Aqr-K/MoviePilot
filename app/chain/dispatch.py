"""模块与插件提供者的三级分发机制。

Dispatcher 绑定一组模块/插件管理器与错误上报组件，完成广播/多播/单播与
run_module 聚合；未显式绑定时使用进程级单例。模块级同名函数是默认分发器
的直接投影，服务按需组合使用，ChainBase 仅保留同名薄转发。
"""

import inspect
import traceback
from collections.abc import Callable
from typing import Any, List, Tuple

from fastapi.concurrency import run_in_threadpool

from app.application.messaging.message import MessageHelper
from app.foundation.reflection import ObjectUtils
from app.runtime.events import EventManager
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.log import logger
from app.schemas import RateLimitExceededException
from app.schemas.types import EventType


def _is_valid_empty(ret: Any) -> bool:
    """判断结果是否为空。"""
    if isinstance(ret, tuple):
        return all(value is None for value in ret)
    return ret is None


class Dispatcher:
    """绑定管理器与错误上报组件的分发器；未绑定的组件使用进程级单例。"""

    def __init__(
            self,
            module_manager: Any = None,
            plugin_manager: Any = None,
            message_helper: Any = None,
            event_manager: Any = None,
    ):
        """按需绑定组件；传 None 表示使用进程级单例。"""
        self._module_manager = module_manager
        self._plugin_manager = plugin_manager
        self._message_helper = message_helper
        self._event_manager = event_manager

    @property
    def module_manager(self) -> Any:
        """当前生效的模块管理器。"""
        return self._module_manager or ModuleManager()

    @property
    def plugin_manager(self) -> Any:
        """当前生效的插件管理器。"""
        return self._plugin_manager or PluginManager()

    @property
    def message_helper(self) -> Any:
        """当前生效的消息中心。"""
        return self._message_helper or MessageHelper()

    @property
    def event_manager(self) -> Any:
        """当前生效的事件总线。"""
        return self._event_manager or EventManager()

    def _handle_plugin_error(
            self, err: Exception, plugin_id: str, plugin_name: str, method: str, **kwargs
    ) -> None:
        """处理插件模块执行错误。"""
        if kwargs.get("raise_exception"):
            raise err
        logger.error(
            f"运行插件 {plugin_id} 模块 {method} 出错：{str(err)}\n{traceback.format_exc()}"
        )
        self.message_helper.put(
            title=f"{plugin_name} 发生了错误", message=str(err), role="plugin"
        )
        self.event_manager.send_event(
            EventType.SystemError,
            {
                "type": "plugin",
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "plugin_method": method,
                "error": str(err),
                "traceback": traceback.format_exc(),
            },
        )

    def _handle_system_error(
            self, err: Exception, module_id: str, module_name: str, method: str, **kwargs
    ) -> None:
        """处理系统模块执行错误。"""
        if kwargs.get("raise_exception"):
            raise err
        logger.error(
            f"运行模块 {module_id}.{method} 出错：{str(err)}\n{traceback.format_exc()}"
        )
        self.message_helper.put(
            title=f"{module_name}发生了错误", message=str(err), role="system"
        )
        self.event_manager.send_event(
            EventType.SystemError,
            {
                "type": "module",
                "module_id": module_id,
                "module_name": module_name,
                "module_method": method,
                "error": str(err),
                "traceback": traceback.format_exc(),
            },
        )

    @staticmethod
    def _handle_rate_limit_error(
            err: RateLimitExceededException, source_type: str, source_id: str,
            method: str, **kwargs
    ) -> None:
        """处理本地限流跳过，避免预期的限流状态进入系统错误告警。"""
        if kwargs.get("raise_exception"):
            raise err
        logger.info(f"{source_type} {source_id}.{method} 已限流，跳过执行：{str(err)}")

    def _invoke_plugin(self, plugin_id: str, plugin_name: str, func: Callable,
                       method: str, *args, **kwargs) -> Any:
        """
        执行插件注入的方法，并按插件语义处理限流与错误

        :return: 插件的返回值，跳过或出错时为 None
        """
        try:
            logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
            return func(*args, **kwargs)
        except RateLimitExceededException as err:
            self._handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
        except Exception as err:
            self._handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return None

    def _invoke_provider(self, module: Any, method: str, *args, **kwargs) -> Any:
        """
        执行单个提供者，并按既有语义处理限流与错误

        :return: 提供者的返回值，跳过或出错时为 None
        """
        module_id = module.__class__.__name__
        try:
            module_name = module.get_name()
        except Exception as err:
            logger.debug(f"获取模块名称出错：{str(err)}")
            module_name = module_id
        try:
            return getattr(module, method)(*args, **kwargs)
        except RateLimitExceededException as err:
            self._handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
        except Exception as err:
            logger.error(traceback.format_exc())
            self._handle_system_error(err, module_id, module_name, method, **kwargs)
        return None

    async def _async_invoke_plugin(self, plugin_id: str, plugin_name: str, func: Callable,
                                   method: str, *args, **kwargs) -> Any:
        """
        异步执行插件注入的方法；同步方法切线程池

        :return: 插件的返回值，跳过或出错时为 None
        """
        try:
            logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return await run_in_threadpool(func, *args, **kwargs)
        except RateLimitExceededException as err:
            self._handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
        except Exception as err:
            self._handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return None

    async def _async_invoke_provider(self, module: Any, method: str, *args, **kwargs) -> Any:
        """
        异步执行单个提供者；同步方法切线程池，避免阻塞共享事件循环

        :return: 提供者的返回值，跳过或出错时为 None
        """
        module_id = module.__class__.__name__
        try:
            module_name = module.get_name()
        except Exception as err:
            logger.debug(f"获取模块名称出错：{str(err)}")
            module_name = module_id
        try:
            func = getattr(module, method)
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return await run_in_threadpool(func, *args, **kwargs)
        except RateLimitExceededException as err:
            self._handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
        except Exception as err:
            logger.error(traceback.format_exc())
            self._handle_system_error(err, module_id, module_name, method, **kwargs)
        return None

    def plugin_providers(self, method: str) -> List[Tuple[str, str, Callable]]:
        """
        取插件经 get_module() 注入的同名方法

        这类方法不属于任何族类，但 run_module 一直会先执行它们。多播与单播若看不见
        它们，把方法从广播迁过来就会让挂在其上的插件静默失效，因此一并纳入提供者。

        :param method: 模块方法名称
        :return: [(插件ID, 插件名, 方法), ...]
        """
        providers = []
        for plugin, module_dict in self.plugin_manager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            func = module_dict.get(method)
            if func:
                providers.append((plugin_id, plugin_name, func))
        return providers

    def broadcast(self, method: str, *args, **kwargs) -> None:
        """
        通知全体提供者，不收集答案

        触达全体是广播的语义，遍历因此是它的固有代价，不做索引化——一旦按订阅关系
        建表，它就变成了多播。每个提供者相互独立：一个抛错只按系统模块错误上报，
        不阻断其余提供者收到通知，也不因谁返回了值而提前中止。

        需要答案的场景用多播或单播，它们经注册表查表，不必付出全体遍历的代价。

        :param method: 模块方法名称
        """
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
        for module in self.module_manager.get_running_modules(method):
            self._invoke_provider(module, method, *args, **kwargs)

    def multicast(self, method: str, *args, **kwargs) -> List[Any]:
        """
        圈定一个族类，收集其中每个提供者的答案

        提供者来自 (族类, 能力) 注册表，命中后为 O(1)，只调用真正提供该能力的 k 个模块。
        提供者返回空表示不认领，不计入结果；单个提供者出错不影响其余答案。

        :param method: 模块方法名称
        :return: 全部非空答案，按优先级顺序排列
        """
        answers = []
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            result = self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
            if result is not None:
                answers.append(result)
        for module in self.module_manager.providers_for(method):
            result = self._invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                answers.append(result)
        return answers

    def unicast(self, method: str, *args, **kwargs) -> Any:
        """
        在族类内仲裁，最终只取一个答案

        候选集与多播完全一致——同一张注册表、同一个优先级顺序，单播只是在其上叠加
        短路：谁先给出非空答案就用谁的，其余提供者不再执行。提供者返回空表示不认领，
        仲裁继续下移；族类内无人认领时返回 None，不回落到广播。

        :param method: 模块方法名称
        :return: 优先级最高且认领了本次调用的提供者的答案
        """
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            result = self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
            if result is not None:
                return result
        for module in self.module_manager.providers_for(method):
            result = self._invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                return result
        return None

    async def async_broadcast(self, method: str, *args, **kwargs) -> None:
        """
        异步通知全体提供者，不收集答案

        与同步广播语义一致：触达全体是它的固有代价，不做索引化。

        :param method: 模块方法名称
        """
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            await self._async_invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
        for module in self.module_manager.get_running_modules(method):
            await self._async_invoke_provider(module, method, *args, **kwargs)

    async def async_multicast(self, method: str, *args, **kwargs) -> List[Any]:
        """
        异步圈定一个族类，收集其中每个提供者的答案

        与同步多播查同一张 (族类, 能力) 注册表。

        :param method: 模块方法名称
        :return: 全部非空答案
        """
        answers = []
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            result = await self._async_invoke_plugin(
                plugin_id, plugin_name, func, method, *args, **kwargs
            )
            if result is not None:
                answers.append(result)
        for module in self.module_manager.providers_for(method):
            result = await self._async_invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                answers.append(result)
        return answers

    async def async_unicast(self, method: str, *args, **kwargs) -> Any:
        """
        异步在族类内仲裁，最终只取一个答案

        候选集与异步多播完全一致，只叠加短路。

        :param method: 模块方法名称
        :return: 优先级最高且认领了本次调用的提供者的答案
        """
        for plugin_id, plugin_name, func in self.plugin_providers(method):
            result = await self._async_invoke_plugin(
                plugin_id, plugin_name, func, method, *args, **kwargs
            )
            if result is not None:
                return result
        for module in self.module_manager.providers_for(method):
            result = await self._async_invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                return result
        return None

    def _execute_plugin_modules(self, method: str, result: Any, *args, **kwargs) -> Any:
        """执行插件模块，按 run_module 聚合语义合并结果。"""
        for plugin, module_dict in self.plugin_manager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method in module_dict:
                func = module_dict[method]
                if func:
                    try:
                        logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                        if _is_valid_empty(result):
                            # 返回None，第一次执行或者需继续执行下一模块
                            result = func(*args, **kwargs)
                        elif isinstance(result, list):
                            # 返回为列表，有多个模块运行结果时进行合并
                            temp = func(*args, **kwargs)
                            if isinstance(temp, list):
                                result.extend(temp)
                        else:
                            break
                    except RateLimitExceededException as err:
                        self._handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
                    except Exception as err:
                        self._handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return result

    async def _async_execute_plugin_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """异步执行插件模块；插件同步函数切线程池，避免阻塞。"""
        for plugin, module_dict in self.plugin_manager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method in module_dict:
                func = module_dict[method]
                if func:
                    try:
                        logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                        if _is_valid_empty(result):
                            # 返回None，第一次执行或者需继续执行下一模块
                            if inspect.iscoroutinefunction(func):
                                result = await func(*args, **kwargs)
                            else:
                                result = await run_in_threadpool(func, *args, **kwargs)
                        elif isinstance(result, list):
                            # 返回为列表，有多个模块运行结果时进行合并
                            if inspect.iscoroutinefunction(func):
                                temp = await func(*args, **kwargs)
                            else:
                                temp = await run_in_threadpool(func, *args, **kwargs)
                            if isinstance(temp, list):
                                result.extend(temp)
                        else:
                            break
                    except RateLimitExceededException as err:
                        self._handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
                    except Exception as err:
                        self._handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return result

    def _execute_system_modules(self, method: str, result: Any, *args, **kwargs) -> Any:
        """执行系统模块，按 run_module 聚合语义合并/传递结果。"""
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self.module_manager.get_running_modules(method),
                key=lambda x: x.get_priority(),
        ):
            module_id = module.__class__.__name__
            try:
                module_name = module.get_name()
            except Exception as err:
                logger.debug(f"获取模块名称出错：{str(err)}")
                module_name = module_id
            try:
                func = getattr(module, method)
                if _is_valid_empty(result):
                    # 返回None，第一次执行或者需继续执行下一模块
                    result = func(*args, **kwargs)
                elif ObjectUtils.check_signature(func, result):
                    # 返回结果与方法签名一致，将结果传入
                    result = func(result)
                elif isinstance(result, list):
                    # 返回为列表，有多个模块运行结果时进行合并
                    temp = func(*args, **kwargs)
                    if isinstance(temp, list):
                        result.extend(temp)
                else:
                    # 中止继续执行
                    break
            except RateLimitExceededException as err:
                self._handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
            except Exception as err:
                logger.error(traceback.format_exc())
                self._handle_system_error(err, module_id, module_name, method, **kwargs)
        return result

    async def _async_execute_system_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """异步执行系统模块；同步模块切线程池，避免阻塞共享事件循环。"""
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self.module_manager.get_running_modules(method),
                key=lambda x: x.get_priority(),
        ):
            module_id = module.__class__.__name__
            try:
                module_name = module.get_name()
            except Exception as err:
                logger.debug(f"获取模块名称出错：{str(err)}")
                module_name = module_id
            try:
                func = getattr(module, method)
                if _is_valid_empty(result):
                    # 返回None，第一次执行或者需继续执行下一模块
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = await run_in_threadpool(func, *args, **kwargs)
                elif ObjectUtils.check_signature(func, result):
                    # 返回结果与方法签名一致，将结果传入
                    if inspect.iscoroutinefunction(func):
                        result = await func(result)
                    else:
                        result = await run_in_threadpool(func, result)
                elif isinstance(result, list):
                    # 返回为列表，有多个模块运行结果时进行合并
                    if inspect.iscoroutinefunction(func):
                        temp = await func(*args, **kwargs)
                    else:
                        temp = await run_in_threadpool(func, *args, **kwargs)
                    if isinstance(temp, list):
                        result.extend(temp)
                else:
                    # 中止继续执行
                    break
            except RateLimitExceededException as err:
                self._handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
            except Exception as err:
                logger.error(traceback.format_exc())
                self._handle_system_error(err, module_id, module_name, method, **kwargs)
        return result

    def run_module(self, method: str, *args, **kwargs) -> Any:
        """
        运行包含该方法的所有模块，然后返回结果
        当kwargs包含命名参数raise_exception时，如模块方法抛出异常且raise_exception为True，则同步抛出异常

        :param method: 模块方法名称
        """
        # 执行插件模块
        result = self._execute_plugin_modules(method, None, *args, **kwargs)

        if not _is_valid_empty(result) and not isinstance(result, list):
            # 插件模块返回结果不为空且不是列表，直接返回
            return result

        # 执行系统模块
        return self._execute_system_modules(method, result, *args, **kwargs)

    async def async_run_module(self, method: str, *args, **kwargs) -> Any:
        """
        异步运行包含该方法的所有模块，然后返回结果
        当kwargs包含命名参数raise_exception时，如模块方法抛出异常且raise_exception为True，则同步抛出异常
        支持异步和同步方法的混合调用

        :param method: 模块方法名称
        """
        # 执行插件模块
        result = await self._async_execute_plugin_modules(method, None, *args, **kwargs)

        if not _is_valid_empty(result) and not isinstance(result, list):
            # 插件模块返回结果不为空且不是列表，直接返回
            return result

        # 执行系统模块
        return await self._async_execute_system_modules(method, result, *args, **kwargs)


_default_dispatcher = Dispatcher()

plugin_providers = _default_dispatcher.plugin_providers
broadcast = _default_dispatcher.broadcast
multicast = _default_dispatcher.multicast
unicast = _default_dispatcher.unicast
async_broadcast = _default_dispatcher.async_broadcast
async_multicast = _default_dispatcher.async_multicast
async_unicast = _default_dispatcher.async_unicast
run_module = _default_dispatcher.run_module
async_run_module = _default_dispatcher.async_run_module
