from __future__ import annotations

import inspect
import pickle
import traceback
from abc import ABCMeta
from collections.abc import Callable
from pathlib import Path
from typing import Optional, Any, Tuple, List, Set, Union, Dict

from fastapi.concurrency import run_in_threadpool

from app.application.messaging.message import MessageHelper, MessageQueueManager
from app.chain._messaging import MessageProcessingMixin, NotificationMixin
from app.chain._recognition import RecognitionMixin
from app.db.oper.message import MessageOper
from app.domain.context import Context, MediaInfo, SubtitleInfo, TorrentInfo
from app.domain.meta.metabase import MetaBase
from app.foundation.reflection import ObjectUtils
from app.runtime.cache import FileCache, AsyncFileCache
from app.runtime.events import EventManager
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.log import logger
from app.schemas import (
    RateLimitExceededException,
    TransferInfo,
    ExistMediaInfo,
    DownloaderTorrent,
    IncomingMessage,
    WebhookEventInfo,
    TmdbEpisode,
    MediaPerson,
    FileItem,
    TransferDirectoryConf,
)
from app.schemas.category import CategoryConfig
from app.schemas.types import (
    TorrentStatus,
    MediaType,
    MediaSource,
    MediaSourceSelection,
    MediaImageType,
    EventType,
    ModuleType,
)


class ChainBase(RecognitionMixin, MessageProcessingMixin, NotificationMixin,
                metaclass=ABCMeta):
    """
    处理链基类
    """

    def __init__(self):
        """
        公共初始化
        """
        self.modulemanager = ModuleManager()
        self.eventmanager = EventManager()
        self.messageoper = MessageOper()
        self.messagehelper = MessageHelper()
        self.messagequeue = MessageQueueManager(send_callback=self.multicast)
        self.pluginmanager = PluginManager()
        self.filecache = FileCache()
        self.async_filecache = AsyncFileCache()

    def load_cache(self, filename: str) -> Any:
        """
        加载缓存
        """
        content = self.filecache.get(filename)
        if not content:
            return None
        try:
            return pickle.loads(content)
        except Exception as err:
            logger.error(f"加载缓存 {filename} 出错：{str(err)}")
            return None

    async def async_load_cache(self, filename: str) -> Any:
        """
        异步加载缓存
        """
        content = await self.async_filecache.get(filename)
        if not content:
            return None
        try:
            return pickle.loads(content)
        except Exception as err:
            logger.error(f"异步加载缓存 {filename} 出错：{str(err)}")
            return None

    async def async_save_cache(self, cache: Any, filename: str) -> None:
        """
        异步保存缓存
        """
        try:
            await self.async_filecache.set(filename, pickle.dumps(cache))
        except Exception as err:
            logger.error(f"异步保存缓存 {filename} 出错：{str(err)}")
            return

    def save_cache(self, cache: Any, filename: str) -> None:
        """
        保存缓存
        """
        try:
            self.filecache.set(filename, pickle.dumps(cache))
        except Exception as err:
            logger.error(f"保存缓存 {filename} 出错：{str(err)}")
            return

    def remove_cache(self, filename: str) -> None:
        """
        删除缓存，同时删除Redis和本地缓存
        """
        self.filecache.delete(filename)

    async def async_remove_cache(self, filename: str) -> None:
        """
        异步删除缓存，同时删除Redis和本地缓存
        """
        await self.async_filecache.delete(filename)

    @staticmethod
    def __is_valid_empty(ret):
        """
        判断结果是否为空
        """
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        else:
            return ret is None

    def __handle_plugin_error(
            self, err: Exception, plugin_id: str, plugin_name: str, method: str, **kwargs
    ):
        """
        处理插件模块执行错误
        """
        if kwargs.get("raise_exception"):
            raise err
        logger.error(
            f"运行插件 {plugin_id} 模块 {method} 出错：{str(err)}\n{traceback.format_exc()}"
        )
        self.messagehelper.put(
            title=f"{plugin_name} 发生了错误", message=str(err), role="plugin"
        )
        self.eventmanager.send_event(
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

    def __handle_system_error(
            self, err: Exception, module_id: str, module_name: str, method: str, **kwargs
    ):
        """
        处理系统模块执行错误
        """
        if kwargs.get("raise_exception"):
            raise err
        logger.error(
            f"运行模块 {module_id}.{method} 出错：{str(err)}\n{traceback.format_exc()}"
        )
        self.messagehelper.put(
            title=f"{module_name}发生了错误", message=str(err), role="system"
        )
        self.eventmanager.send_event(
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
    def __handle_rate_limit_error(
            err: RateLimitExceededException, source_type: str, source_id: str,
            method: str, **kwargs
    ) -> None:
        """
        处理本地限流跳过，避免预期的限流状态进入系统错误告警。
        """
        if kwargs.get("raise_exception"):
            raise err
        logger.info(f"{source_type} {source_id}.{method} 已限流，跳过执行：{str(err)}")

    def __execute_plugin_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """
        执行插件模块
        """
        for plugin, module_dict in self.pluginmanager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method in module_dict:
                func = module_dict[method]
                if func:
                    try:
                        logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                        if self.__is_valid_empty(result):
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
                        self.__handle_rate_limit_error(
                            err, "插件", plugin_id, method, **kwargs
                        )
                    except Exception as err:
                        self.__handle_plugin_error(
                            err, plugin_id, plugin_name, method, **kwargs
                        )
        return result

    async def __async_execute_plugin_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """
        异步执行插件模块
        """
        for plugin, module_dict in self.pluginmanager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method in module_dict:
                func = module_dict[method]
                if func:
                    try:
                        logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                        if self.__is_valid_empty(result):
                            # 返回None，第一次执行或者需继续执行下一模块
                            if inspect.iscoroutinefunction(func):
                                result = await func(*args, **kwargs)
                            else:
                                # 插件同步函数在异步环境中运行，避免阻塞
                                result = await run_in_threadpool(func, *args, **kwargs)
                        elif isinstance(result, list):
                            # 返回为列表，有多个模块运行结果时进行合并
                            if inspect.iscoroutinefunction(func):
                                temp = await func(*args, **kwargs)
                            else:
                                # 插件同步函数在异步环境中运行，避免阻塞
                                temp = await run_in_threadpool(func, *args, **kwargs)
                            if isinstance(temp, list):
                                result.extend(temp)
                        else:
                            break
                    except RateLimitExceededException as err:
                        self.__handle_rate_limit_error(
                            err, "插件", plugin_id, method, **kwargs
                        )
                    except Exception as err:
                        self.__handle_plugin_error(
                            err, plugin_id, plugin_name, method, **kwargs
                        )
        return result

    def __execute_system_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """
        执行系统模块
        """
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self.modulemanager.get_running_modules(method),
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
                if self.__is_valid_empty(result):
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
                self.__handle_rate_limit_error(
                    err, "模块", module_id, method, **kwargs
                )
            except Exception as err:
                logger.error(traceback.format_exc())
                self.__handle_system_error(
                    err, module_id, module_name, method, **kwargs
                )
        return result

    async def __async_execute_system_modules(
            self, method: str, result: Any, *args, **kwargs
    ) -> Any:
        """
        异步执行系统模块
        """
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self.modulemanager.get_running_modules(method),
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
                if self.__is_valid_empty(result):
                    # 返回None，第一次执行或者需继续执行下一模块
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        # 系统同步模块在异步路径里也必须切到线程池，避免阻塞共享事件循环。
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
                self.__handle_rate_limit_error(
                    err, "模块", module_id, method, **kwargs
                )
            except Exception as err:
                logger.error(traceback.format_exc())
                self.__handle_system_error(
                    err, module_id, module_name, method, **kwargs
                )
        return result

    def _invoke_provider(self, module: Any, method: str, *args, **kwargs) -> Any:
        """
        执行单个提供者，并按既有语义处理限流与错误

        :param module: 提供者模块实例
        :param method: 模块方法名称
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
            self.__handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
        except Exception as err:
            logger.error(traceback.format_exc())
            self.__handle_system_error(err, module_id, module_name, method, **kwargs)
        return None

    def broadcast(self, method: str, *args, **kwargs) -> None:
        """
        通知全体提供者，不收集答案

        触达全体是广播的语义，遍历因此是它的固有代价，不做索引化——一旦按订阅关系
        建表，它就变成了多播。每个提供者相互独立：一个抛错只按系统模块错误上报，
        不阻断其余提供者收到通知，也不因谁返回了值而提前中止。

        需要答案的场景用多播或单播，它们经注册表查表，不必付出全体遍历的代价。

        :param method: 模块方法名称
        """
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
        for module in self.modulemanager.get_running_modules(method):
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
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            result = self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
            if result is not None:
                answers.append(result)
        for module in self.modulemanager.providers_for(method):
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
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            result = self._invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
            if result is not None:
                return result
        for module in self.modulemanager.providers_for(method):
            result = self._invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                return result
        return None

    def _plugin_providers(self, method: str) -> List[Tuple[str, str, Callable]]:
        """
        取插件经 get_module() 注入的同名方法

        这类方法不属于任何族类，但 run_module 一直会先执行它们。多播与单播若看不见
        它们，把方法从广播迁过来就会让挂在其上的插件静默失效，因此一并纳入提供者。

        :param method: 模块方法名称
        :return: [(插件ID, 插件名, 方法), ...]
        """
        providers = []
        for plugin, module_dict in self.pluginmanager.get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            func = module_dict.get(method)
            if func:
                providers.append((plugin_id, plugin_name, func))
        return providers

    def _invoke_plugin(self, plugin_id: str, plugin_name: str, func: Callable,
                       method: str, *args, **kwargs) -> Any:
        """
        执行插件注入的方法，并按插件语义处理限流与错误

        :param plugin_id: 插件标识
        :param plugin_name: 插件名称
        :param func: 插件注入的方法
        :param method: 模块方法名称
        :return: 插件的返回值，跳过或出错时为 None
        """
        try:
            logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
            return func(*args, **kwargs)
        except RateLimitExceededException as err:
            self.__handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
        except Exception as err:
            self.__handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return None

    async def _async_invoke_provider(self, module: Any, method: str, *args, **kwargs) -> Any:
        """
        异步执行单个提供者；同步方法切线程池，避免阻塞共享事件循环

        :param module: 提供者模块实例
        :param method: 模块方法名称
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
            self.__handle_rate_limit_error(err, "模块", module_id, method, **kwargs)
        except Exception as err:
            logger.error(traceback.format_exc())
            self.__handle_system_error(err, module_id, module_name, method, **kwargs)
        return None

    async def _async_invoke_plugin(self, plugin_id: str, plugin_name: str, func: Callable,
                                   method: str, *args, **kwargs) -> Any:
        """
        异步执行插件注入的方法；同步方法切线程池

        :param plugin_id: 插件标识
        :param plugin_name: 插件名称
        :param func: 插件注入的方法
        :param method: 模块方法名称
        :return: 插件的返回值，跳过或出错时为 None
        """
        try:
            logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return await run_in_threadpool(func, *args, **kwargs)
        except RateLimitExceededException as err:
            self.__handle_rate_limit_error(err, "插件", plugin_id, method, **kwargs)
        except Exception as err:
            self.__handle_plugin_error(err, plugin_id, plugin_name, method, **kwargs)
        return None

    async def async_broadcast(self, method: str, *args, **kwargs) -> None:
        """
        异步通知全体提供者，不收集答案

        与同步广播语义一致：触达全体是它的固有代价，不做索引化。

        :param method: 模块方法名称
        """
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            await self._async_invoke_plugin(plugin_id, plugin_name, func, method, *args, **kwargs)
        for module in self.modulemanager.get_running_modules(method):
            await self._async_invoke_provider(module, method, *args, **kwargs)

    async def async_multicast(self, method: str, *args, **kwargs) -> List[Any]:
        """
        异步圈定一个族类，收集其中每个提供者的答案

        与同步多播查同一张 (族类, 能力) 注册表。

        :param method: 模块方法名称
        :return: 全部非空答案
        """
        answers = []
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            result = await self._async_invoke_plugin(
                plugin_id, plugin_name, func, method, *args, **kwargs
            )
            if result is not None:
                answers.append(result)
        for module in self.modulemanager.providers_for(method):
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
        for plugin_id, plugin_name, func in self._plugin_providers(method):
            result = await self._async_invoke_plugin(
                plugin_id, plugin_name, func, method, *args, **kwargs
            )
            if result is not None:
                return result
        for module in self.modulemanager.providers_for(method):
            result = await self._async_invoke_provider(module, method, *args, **kwargs)
            if result is not None:
                return result
        return None

    def run_module(
            self,
            method: str,
            *args,
            **kwargs,
    ) -> Any:
        """
        运行包含该方法的所有模块，然后返回结果
        当kwargs包含命名参数raise_exception时，如模块方法抛出异常且raise_exception为True，则同步抛出异常

        :param method: 模块方法名称
        """
        # 执行插件模块
        result = self.__execute_plugin_modules(method, None, *args, **kwargs)

        if not self.__is_valid_empty(result) and not isinstance(result, list):
            # 插件模块返回结果不为空且不是列表，直接返回
            return result

        # 执行系统模块
        return self.__execute_system_modules(method, result, *args, **kwargs)

    async def async_run_module(
            self,
            method: str,
            *args,
            **kwargs,
    ) -> Any:
        """
        异步运行包含该方法的所有模块，然后返回结果
        当kwargs包含命名参数raise_exception时，如模块方法抛出异常且raise_exception为True，则同步抛出异常
        支持异步和同步方法的混合调用

        :param method: 模块方法名称
        """
        # 执行插件模块
        result = await self.__async_execute_plugin_modules(
            method, None, *args, **kwargs
        )

        if not self.__is_valid_empty(result) and not isinstance(result, list):
            # 插件模块返回结果不为空且不是列表，直接返回
            return result

        # 执行系统模块
        return await self.__async_execute_system_modules(
            method, result, *args, **kwargs
        )

    def match_doubaninfo(
            self,
            name: str,
            imdbid: Optional[str] = None,
            mtype: Optional[MediaType] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
            raise_exception: bool = False,
    ) -> Optional[dict]:
        """
        搜索和匹配豆瓣信息
        :param name: 标题
        :param imdbid: imdbid
        :param mtype: 类型
        :param year: 年份
        :param season: 季
        :param raise_exception: 触发速率限制时是否抛出异常
        """
        return self.unicast(
            "match_media",
            source=MediaSource.Douban,
            name=name,
            imdbid=imdbid,
            mtype=mtype,
            year=year,
            season=season,
            raise_exception=raise_exception,
        )

    async def async_match_doubaninfo(
            self,
            name: str,
            imdbid: Optional[str] = None,
            mtype: Optional[MediaType] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
            raise_exception: bool = False,
    ) -> Optional[dict]:
        """
        搜索和匹配豆瓣信息（异步版本）
        :param name: 标题
        :param imdbid: imdbid
        :param mtype: 类型
        :param year: 年份
        :param season: 季
        :param raise_exception: 触发速率限制时是否抛出异常
        """
        return await self.async_unicast(
            "async_match_media",
            source=MediaSource.Douban,
            name=name,
            imdbid=imdbid,
            mtype=mtype,
            year=year,
            season=season,
            raise_exception=raise_exception,
        )

    def match_tmdbinfo(
            self,
            name: str,
            mtype: Optional[MediaType] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
    ) -> Optional[dict]:
        """
        搜索和匹配TMDB信息
        :param name: 标题
        :param mtype: 类型
        :param year: 年份
        :param season: 季
        """
        return self.unicast(
            "match_media", source=MediaSource.TMDB,
            name=name, mtype=mtype, year=year, season=season,
        )

    async def async_match_tmdbinfo(
            self,
            name: str,
            mtype: Optional[MediaType] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
    ) -> Optional[dict]:
        """
        搜索和匹配TMDB信息（异步版本）
        :param name: 标题
        :param mtype: 类型
        :param year: 年份
        :param season: 季
        """
        return await self.async_unicast(
            "async_match_media", source=MediaSource.TMDB,
            name=name, mtype=mtype, year=year, season=season,
        )

    def obtain_images(self, mediainfo: MediaInfo) -> Optional[MediaInfo]:
        """
        补充抓取媒体信息图片
        :param mediainfo:  识别的媒体信息
        :return: 更新后的媒体信息
        """
        if mediainfo and mediainfo.type == MediaType.MUSIC:
            return mediainfo
        return self.run_module("obtain_images", mediainfo=mediainfo)

    async def async_obtain_images(self, mediainfo: MediaInfo) -> Optional[MediaInfo]:
        """
        补充抓取媒体信息图片（异步版本）
        :param mediainfo:  识别的媒体信息
        :return: 更新后的媒体信息
        """
        if mediainfo and mediainfo.type == MediaType.MUSIC:
            return mediainfo
        return await self.async_run_module("async_obtain_images", mediainfo=mediainfo)

    def obtain_specific_image(
            self,
            mediaid: Union[str, int],
            mtype: MediaType,
            image_type: MediaImageType,
            image_prefix: Optional[str] = None,
            season: Optional[int] = None,
            episode: Optional[int] = None,
    ) -> Optional[str]:
        """
        获取指定媒体信息图片，返回图片地址
        :param mediaid:     媒体ID
        :param mtype:       媒体类型
        :param image_type:  图片类型
        :param image_prefix: 图片前缀
        :param season:      季
        :param episode:     集
        """
        return self.unicast(
            "obtain_specific_image",
            mediaid=mediaid,
            mtype=mtype,
            image_prefix=image_prefix,
            image_type=image_type,
            season=season,
            episode=episode,
        )

    def douban_info(
            self,
            doubanid: str,
            mtype: Optional[MediaType] = None,
            raise_exception: bool = False,
    ) -> Optional[dict]:
        """
        获取豆瓣信息
        :param doubanid: 豆瓣ID
        :param mtype: 媒体类型
        :return: 豆瓣信息
        :param raise_exception: 触发速率限制时是否抛出异常
        """
        return self.unicast(
            "media_detail",
            source=MediaSource.Douban,
            media_id=doubanid,
            mtype=mtype,
            raise_exception=raise_exception,
        )

    async def async_douban_info(
            self,
            doubanid: str,
            mtype: Optional[MediaType] = None,
            raise_exception: bool = False,
    ) -> Optional[dict]:
        """
        获取豆瓣信息（异步版本）
        :param doubanid: 豆瓣ID
        :param mtype: 媒体类型
        :return: 豆瓣信息
        :param raise_exception: 触发速率限制时是否抛出异常
        """
        return await self.async_unicast(
            "async_media_detail",
            source=MediaSource.Douban,
            media_id=doubanid,
            mtype=mtype,
            raise_exception=raise_exception,
        )

    def tvdb_info(self, tvdbid: int) -> Optional[dict]:
        """
        获取TVDB信息
        :param tvdbid: int
        :return: TVDB信息
        """
        return self.unicast("media_detail", source=MediaSource.TVDB, media_id=tvdbid)

    def tvdb_slug(self, tvdbid: int) -> Optional[str]:
        """
        获取TVDB剧集 slug（别名），用于构建 TheTvDb 直达链接。
        :param tvdbid: int
        :return: slug 字符串
        """
        return self.unicast("tvdb_slug", tvdbid=tvdbid)

    def tmdb_info(
            self, tmdbid: int, mtype: MediaType, season: Optional[int] = None
    ) -> Optional[dict]:
        """
        获取TMDB信息
        :param tmdbid: int
        :param mtype:  媒体类型
        :param season: 季
        :return: TVDB信息
        """
        return self.unicast("media_detail", source=MediaSource.TMDB,
                            media_id=tmdbid, mtype=mtype, season=season)

    async def async_tmdb_info(
            self, tmdbid: int, mtype: MediaType, season: Optional[int] = None
    ) -> Optional[dict]:
        """
        获取TMDB信息（异步版本）
        :param tmdbid: int
        :param mtype:  媒体类型
        :param season: 季
        :return: TVDB信息
        """
        return await self.async_unicast(
            "async_media_detail", source=MediaSource.TMDB,
            media_id=tmdbid, mtype=mtype, season=season
        )

    def bangumi_info(self, bangumiid: int) -> Optional[dict]:
        """
        获取Bangumi信息
        :param bangumiid: int
        :return: Bangumi信息
        """
        return self.unicast("media_detail", source=MediaSource.Bangumi, media_id=bangumiid)

    async def async_bangumi_info(self, bangumiid: int) -> Optional[dict]:
        """
        获取Bangumi信息（异步版本）
        :param bangumiid: int
        :return: Bangumi信息
        """
        return await self.async_unicast("async_media_detail",
                                        source=MediaSource.Bangumi, media_id=bangumiid)

    def message_parser(
            self, source: str, body: Any, form: Any, args: Any
    ) -> Optional[IncomingMessage]:
        """
        解析消息内容，返回字典，注意以下约定值：
        userid: 用户ID
        username: 用户名
        text: 内容
        :param source: 消息来源（渠道配置名称）
        :param body: 请求体
        :param form: 表单
        :param args: 参数
        :return: 消息渠道、消息内容
        """
        return self.unicast(
            "message_parser", source=source, body=body, form=form, args=args
        )

    def webhook_parser(
            self, body: Any, form: Any, args: Any
    ) -> Optional[WebhookEventInfo]:
        """
        解析Webhook报文体
        :param body:  请求体
        :param form:  请求表单
        :param args:  请求参数
        :return: 字典，解析为消息时需要包含：title、text、image
        """
        return self.unicast("webhook_parser", body=body, form=form, args=args)

    def search_medias(
            self, meta: MetaBase, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaInfo]]:
        """
        搜索媒体信息
        :param meta:  识别的元数据
        :param media_source: 请求级搜索数据源
        :return: 媒体信息列表
        """
        medias = [
            media
            for group in self.multicast(
                "search_medias", meta=meta, media_source=media_source
            )
            for media in group
        ]
        return medias or None

    async def async_search_medias(
            self, meta: MetaBase, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaInfo]]:
        """
        搜索媒体信息（异步版本）
        :param meta:  识别的元数据
        :param media_source: 请求级搜索数据源
        :return: 媒体信息列表
        """
        medias = [
            media
            for group in await self.async_multicast(
                "async_search_medias", meta=meta, media_source=media_source
            )
            for media in group
        ]
        return medias or None

    def search_persons(
            self, name: str, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaPerson]]:
        """
        搜索人物信息
        :param name:  人物名称
        :param media_source: 请求级搜索数据源
        :return: 人物信息列表
        """
        persons = [
            person
            for group in self.multicast(
                "search_persons", name=name, media_source=media_source
            )
            for person in group
        ]
        return persons or None

    async def async_search_persons(
            self, name: str, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaPerson]]:
        """
        搜索人物信息（异步版本）
        :param name:  人物名称
        :param media_source: 请求级搜索数据源
        :return: 人物信息列表
        """
        persons = [
            person
            for group in await self.async_multicast(
                "async_search_persons", name=name, media_source=media_source
            )
            for person in group
        ]
        return persons or None

    def search_collections(
            self, name: str, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaInfo]]:
        """
        搜索集合信息
        :param name:  集合名称
        :param media_source: 请求级搜索数据源
        :return: 合集信息列表
        """
        collections = [
            collection
            for group in self.multicast(
                "search_collections", name=name, media_source=media_source
            )
            for collection in group
        ]
        return collections or None

    async def async_search_collections(
            self, name: str, media_source: Optional[MediaSourceSelection] = None
    ) -> Optional[List[MediaInfo]]:
        """
        搜索集合信息（异步版本）
        :param name:  集合名称
        :param media_source: 请求级搜索数据源
        :return: 合集信息列表
        """
        collections = [
            collection
            for group in await self.async_multicast(
                "async_search_collections", name=name, media_source=media_source
            )
            for collection in group
        ]
        return collections or None

    def get_search_page_size(
            self,
            site: dict,
            keyword: Optional[str] = None,
    ) -> Optional[int]:
        """
        获取站点搜索单页容量；返回 None 表示当前搜索入口不支持可靠翻页。
        """
        return self.unicast(
            "get_search_page_size", site=site, keyword=keyword
        )

    def search_torrents(
            self,
            site: dict,
            keyword: str,
            mtype: Optional[MediaType] = None,
            page: Optional[int] = 0,
    ) -> List[TorrentInfo]:
        """
        搜索一个站点的种子资源
        :param site:  站点
        :param keyword:  搜索关键词
        :param mtype:  媒体类型
        :param page:  页码
        :reutrn: 资源列表
        """
        return self.unicast(
            "search_torrents", site=site, keyword=keyword, mtype=mtype, page=page
        )

    def search_subtitles(
            self,
            site: dict,
            keyword: str,
            page: Optional[int] = 0,
    ) -> List[SubtitleInfo]:
        """
        搜索一个站点的字幕资源。
        :param site: 站点
        :param keyword: 搜索关键词
        :param page: 页码
        :return: 字幕列表
        """
        return self.unicast(
            "search_subtitles", site=site, keyword=keyword, page=page
        )

    async def async_search_torrents(
            self,
            site: dict,
            keyword: str,
            mtype: Optional[MediaType] = None,
            page: Optional[int] = 0,
    ) -> List[TorrentInfo]:
        """
        异步搜索一个站点的种子资源
        :param site:  站点
        :param keyword:  搜索关键词
        :param mtype:  媒体类型
        :param page:  页码
        :reutrn: 资源列表
        """
        return await self.async_unicast(
            "async_search_torrents", site=site, keyword=keyword, mtype=mtype, page=page
        )

    async def async_search_subtitles(
            self,
            site: dict,
            keyword: str,
            page: Optional[int] = 0,
    ) -> List[SubtitleInfo]:
        """
        异步搜索一个站点的字幕资源。
        :param site: 站点
        :param keyword: 搜索关键词
        :param page: 页码
        :return: 字幕列表
        """
        return await self.async_unicast(
            "async_search_subtitles", site=site, keyword=keyword, page=page
        )

    def refresh_torrents(
            self,
            site: dict,
            keyword: Optional[str] = None,
            cat: Optional[str] = None,
            page: Optional[int] = 0,
            mtype: Optional[MediaType] = None,
    ) -> List[TorrentInfo]:
        """
        获取站点最新一页的种子，多个站点需要多线程处理
        :param site:  站点
        :param keyword:  标题
        :param cat:  分类
        :param page:  页码
        :param mtype: 媒体类型
        :reutrn: 种子资源列表
        """
        return self.unicast(
            "refresh_torrents", site=site, keyword=keyword, cat=cat, page=page, mtype=mtype
        )

    async def async_refresh_torrents(
            self,
            site: dict,
            keyword: Optional[str] = None,
            cat: Optional[str] = None,
            page: Optional[int] = 0,
            mtype: Optional[MediaType] = None,
    ) -> List[TorrentInfo]:
        """
        异步获取站点最新一页的种子，多个站点需要多线程处理
        :param site:  站点
        :param keyword:  标题
        :param cat:  分类
        :param page:  页码
        :param mtype: 媒体类型
        :reutrn: 种子资源列表
        """
        return await self.async_unicast(
            "async_refresh_torrents", site=site, keyword=keyword, cat=cat, page=page, mtype=mtype
        )

    def filter_torrents(
            self,
            rule_groups: List[str],
            torrent_list: List[TorrentInfo],
            mediainfo: MediaInfo = None,
    ) -> List[TorrentInfo]:
        """
        过滤种子资源
        :param rule_groups:  过滤规则组名称列表
        :param torrent_list:  资源列表
        :param mediainfo:  识别的媒体信息
        :return: 过滤后的资源列表，添加资源优先级
        """
        return self.unicast(
            "filter_torrents",
            rule_groups=rule_groups,
            torrent_list=torrent_list,
            mediainfo=mediainfo,
        )

    def download(
            self,
            content: Union[Path, str, bytes],
            download_dir: Path,
            cookie: str,
            episodes: Set[int] = None,
            category: Optional[str] = None,
            label: Optional[str] = None,
            downloader: Optional[str] = None,
    ) -> Optional[Tuple[Optional[str], Optional[str], Optional[str], str]]:
        """
        根据种子文件，选择并添加下载任务
        :param content:  种子文件地址或者磁力链接或者种子内容
        :param download_dir:  下载目录
        :param cookie:  cookie
        :param episodes:  需要下载的集数
        :param category:  种子分类
        :param label:  标签
        :param downloader:  下载器
        :return: 下载器名称、种子Hash、种子文件布局、错误原因
        """
        return self.unicast(
            "download",
            content=content,
            download_dir=download_dir,
            cookie=cookie,
            episodes=episodes,
            category=category,
            label=label,
            downloader=downloader,
        )

    def download_added(
            self,
            context: Context,
            download_dir: Path,
            torrent_content: Union[str, bytes] = None,
    ) -> None:
        """
        添加下载任务成功后的模块附加处理分发，站点字幕下载由 DownloadChain 另行编排
        :param context:  上下文，包括识别信息、媒体信息、种子信息
        :param download_dir:  下载目录
        :param torrent_content: 种子内容，如果有则直接使用该内容，否则从 context 中获取种子文件路径
        :return: None，该方法可被多个模块同时处理
        """
        self.broadcast(
            "download_added",
            context=context,
            torrent_content=torrent_content,
            download_dir=download_dir,
        )

    def list_torrents(
            self,
            status: TorrentStatus = None,
            hashs: Union[list, str] = None,
            downloader: Optional[str] = None,
            include_all_tags: bool = False,
    ) -> Optional[List[DownloaderTorrent]]:
        """
        获取下载器种子列表
        :param status:  种子状态
        :param hashs:  种子Hash
        :param downloader:  下载器
        :param include_all_tags:  是否包含未打内置标签的下载任务
        :return: 下载器中符合状态的种子列表
        """
        torrents = [
            torrent
            for group in self.multicast(
                "list_torrents",
                status=status,
                hashs=hashs,
                downloader=downloader,
                include_all_tags=include_all_tags,
            )
            for torrent in group
        ]
        return torrents or None

    def transfer(
            self,
            fileitem: FileItem,
            meta: MetaBase,
            mediainfo: MediaInfo,
            target_directory: TransferDirectoryConf = None,
            target_storage: Optional[str] = None,
            target_path: Path = None,
            transfer_type: Optional[str] = None,
            scrape: bool = None,
            library_type_folder: bool = None,
            library_category_folder: bool = None,
            episodes_info: List[TmdbEpisode] = None,
            source_oper: Callable = None,
            target_oper: Callable = None,
            preview: bool = False,
    ) -> Optional[TransferInfo]:
        """
        文件转移
        :param fileitem:  文件信息
        :param meta: 预识别的元数据
        :param mediainfo:  识别的媒体信息
        :param target_directory:  目标目录配置
        :param target_storage:  目标存储
        :param target_path:  目标路径
        :param transfer_type:  转移模式
        :param scrape: 是否刮削元数据
        :param library_type_folder: 是否按类型创建目录
        :param library_category_folder: 是否按类别创建目录
        :param episodes_info: 当前季的全部集信息
        :param source_oper:  源存储操作类
        :param target_oper:  目标存储操作类
        :param preview: 是否仅预览，不执行实际转移
        :return: {path, target_path, message}
        """
        return self.unicast(
            "transfer",
            fileitem=fileitem,
            meta=meta,
            mediainfo=mediainfo,
            target_directory=target_directory,
            target_path=target_path,
            target_storage=target_storage,
            transfer_type=transfer_type,
            scrape=scrape,
            library_type_folder=library_type_folder,
            library_category_folder=library_category_folder,
            episodes_info=episodes_info,
            source_oper=source_oper,
            target_oper=target_oper,
            preview=preview,
        )

    def transfer_completed(self, hashs: str, downloader: Optional[str] = None) -> None:
        """
        下载器转移完成后的处理
        :param hashs:  种子Hash
        :param downloader:  下载器
        """
        self.broadcast("transfer_completed", hashs=hashs, downloader=downloader)

    def remove_torrents(
            self,
            hashs: Union[str, list],
            delete_file: bool = True,
            downloader: Optional[str] = None,
    ) -> bool:
        """
        删除下载器种子
        :param hashs:  种子Hash
        :param delete_file: 是否删除文件
        :param downloader:  下载器
        :return: bool
        """
        return self.unicast(
            "remove_torrents",
            hashs=hashs,
            delete_file=delete_file,
            downloader=downloader,
        )

    def start_torrents(
            self, hashs: Union[list, str], downloader: Optional[str] = None
    ) -> bool:
        """
        开始下载
        :param hashs:  种子Hash
        :param downloader:  下载器
        :return: bool
        """
        return self.unicast("start_torrents", hashs=hashs, downloader=downloader)

    def stop_torrents(
            self, hashs: Union[list, str], downloader: Optional[str] = None
    ) -> bool:
        """
        停止下载
        :param hashs:  种子Hash
        :param downloader:  下载器
        :return: bool
        """
        return self.unicast("stop_torrents", hashs=hashs, downloader=downloader)

    def set_torrents_tag(
            self, hashs: Union[list, str], tags: list, downloader: Optional[str] = None
    ) -> bool:
        """
        设置种子标签
        :param hashs:  种子Hash
        :param tags:  标签列表
        :param downloader:  下载器
        :return: bool
        """
        return self.unicast("set_torrents_tag", hashs=hashs, tags=tags, downloader=downloader)

    def update_torrent(
            self,
            hash_string: str,
            downloader: Optional[str] = None,
            download_limit: Optional[float] = None,
            upload_limit: Optional[float] = None,
            tracker_list: Optional[list] = None,
            save_path: Optional[str] = None,
            category: Optional[str] = None,
            ratio_limit: Optional[float] = None,
            seeding_time_limit: Optional[int] = None,
    ) -> Optional[Dict[str, bool]]:
        """
        修改下载任务属性。
        :param hash_string: 种子Hash
        :param downloader: 下载器
        :param download_limit: 下载限速，单位 KB/s
        :param upload_limit: 上传限速，单位 KB/s
        :param tracker_list: Tracker URL列表
        :param save_path: 保存目录
        :param category: 分类
        :param ratio_limit: 分享率限制
        :param seeding_time_limit: 做种时间限制，单位分钟
        :return: 各项修改结果
        """
        return self.unicast(
            "update_torrent",
            hash_string=hash_string,
            downloader=downloader,
            download_limit=download_limit,
            upload_limit=upload_limit,
            tracker_list=tracker_list,
            save_path=save_path,
            category=category,
            ratio_limit=ratio_limit,
            seeding_time_limit=seeding_time_limit,
        )

    def get_torrent_trackers(
            self,
            hash_string: str,
            downloader: Optional[str] = None,
    ) -> Optional[Dict[str, List[str]]]:
        """
        查询下载任务Tracker列表。
        :param hash_string: 种子Hash
        :param downloader: 下载器
        :return: 下载器名称到Tracker列表的映射
        """
        return self.unicast(
            "get_torrent_trackers",
            hash_string=hash_string,
            downloader=downloader,
        )

    def torrent_files(
            self, tid: str, downloader: Optional[str] = None
    ) -> Optional[Any]:
        """
        获取种子文件
        :param tid:  种子Hash
        :param downloader:  下载器
        :return: 种子文件，具体类型由下载器实现决定（链层不引入下载器协议类型）
        """
        return self.unicast("torrent_files", tid=tid, downloader=downloader)

    def media_exists(
            self,
            mediainfo: MediaInfo,
            itemid: Optional[str] = None,
            server: Optional[str] = None,
    ) -> Optional[ExistMediaInfo]:
        """
        判断媒体文件是否存在
        :param mediainfo:  识别的媒体信息
        :param itemid:  媒体服务器ItemID
        :param server:  媒体服务器
        :return: 如不存在返回None，存在时返回信息，包括每季已存在所有集{type: movie/tv, seasons: {season: [episodes]}}
        """
        return self.unicast(
            "media_exists", mediainfo=mediainfo, itemid=itemid, server=server
        )

    def media_files(self, mediainfo: MediaInfo) -> Optional[List[FileItem]]:
        """
        获取媒体文件清单
        :param mediainfo:  识别的媒体信息
        :return: 媒体文件列表
        """
        return self.unicast("media_files", mediainfo=mediainfo)

    def metadata_img(
            self,
            mediainfo: MediaInfo,
            season: Optional[int] = None,
            episode: Optional[int] = None,
    ) -> Optional[dict]:
        """
        获取图片名称和url
        :param mediainfo: 媒体信息
        :param season: 季号
        :param episode: 集号
        """
        return self.unicast(
            "metadata_img", mediainfo=mediainfo, season=season, episode=episode
        )

    def media_category(self) -> Optional[Dict[str, list]]:
        """
        获取媒体分类
        :return: 获取二级分类配置字典项，需包括电影、电视剧
        """
        return self.unicast("media_category")

    def category_config(self) -> CategoryConfig:
        """
        获取分类策略配置
        """
        return self.unicast("load_category_config")

    def save_category_config(self, config: CategoryConfig) -> bool:
        """
        保存分类策略配置
        """
        return self.unicast("save_category_config", config=config)

    def register_commands(self, commands: Dict[str, dict]) -> None:
        """
        注册菜单命令
        """
        self.broadcast("register_commands", commands=commands)

    def scheduler_job(self) -> None:
        """
        定时任务，每10分钟调用一次，模块实现该接口以实现定时服务
        """
        self.broadcast("scheduler_job")

    def clear_cache(self) -> None:
        """
        清理缓存，模块实现该接口响应清理缓存事件
        """
        self.broadcast("clear_cache")
