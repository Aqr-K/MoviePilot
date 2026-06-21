import traceback
from typing import Any, List, Optional

from fastapi.concurrency import run_in_threadpool

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class MediaRecognizeManager(metaclass=Singleton):
    """
    媒体识别 / 数据源（MediaRecognize 域）统一入口（单例）。

    对外提供一组识别操作方法（契约见 app.modules.IMediaRecognize），按方法名分两步分发：先经各已启用
    插件注册的同名方法，再到系统数据源后端模块（内建 TheMovieDb/Douban/Bangumi/TheTvDb 及插件经
    provides_data_sources() 注册的源）。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的源。

    识别为管道域：recognize_media 等方法的结果在数据源之间流转、逐源精化（结果可作为下一源入参时透传）；
    search_* 列表方法跨源合并；首个非空非列表结果短路。后端按需实现子集，按方法名分发自然只命中实现者。
    同步方法走 dispatch，异步方法（async_*）走 async_dispatch（同步后端经线程池执行，避免阻塞事件循环）。

    对外方法的参数原样转发到后端（各方法的参数见下方说明及 app.modules.IMediaRecognize）。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    # ------------------------------------------------------------------ #
    # 错误/空值处理
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """判断分发结果是否为空：元组需全部为 None，其余按 is None 判断。"""
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        return ret is None

    def _handle_system_error(self, err: Exception, module_id: str, module_name: str,
                             method: str, raise_exception: bool) -> None:
        """
        系统后端方法出错的处理：raise_exception 为真时直接抛出；否则记录错误日志、推送系统错误消息
        （role=system）、广播 SystemError 事件后继续下一个后端。
        """
        if raise_exception:
            raise err
        logger.error(f"运行模块 {module_id}.{method} 出错：{str(err)}\n{traceback.format_exc()}")
        self._messagehelper.put(title=f"{module_name}发生了错误", message=str(err), role="system")
        eventmanager.send_event(
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

    def _handle_plugin_error(self, err: Exception, plugin_id: str, plugin_name: str,
                            method: str, raise_exception: bool) -> None:
        """
        插件方法出错的处理：raise_exception 为真时直接抛出；否则记录错误日志、推送插件错误消息
        （role=plugin）、广播 SystemError 事件后继续下一个插件。
        """
        if raise_exception:
            raise err
        logger.error(f"运行插件 {plugin_id} 模块 {method} 出错：{str(err)}\n{traceback.format_exc()}")
        self._messagehelper.put(title=f"{plugin_name} 发生了错误", message=str(err), role="plugin")
        eventmanager.send_event(
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

    @staticmethod
    def _handle_rate_limit_error(err: RateLimitExceededException, owner: str, ident: str,
                                 method: str, raise_exception: bool) -> None:
        """
        触发限流时的处理：raise_exception 为真时直接抛出；否则仅记录 INFO 并跳过
        （限流为预期状态，不作系统告警）。
        """
        if raise_exception:
            raise err
        logger.info(f"{owner} {ident}.{method} 已限流，跳过执行：{str(err)}")

    # ------------------------------------------------------------------ #
    # 同步分发内核：插件钩子面 + 系统后端面
    # ------------------------------------------------------------------ #

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """
        依次调用各已启用插件注册的同名方法，按合并规则累积结果。

        :param method: 方法名
        :param result: 已累积的结果，用于判定空值合并 / 列表合并 / 短路
        :param raise_exception: 出错时是否抛出；同时随调用透传给插件方法
        :return: 累积后的结果
        """
        from app.helper.plugin_manager import PluginManager
        # raise_exception 随调用透传给插件方法（插件可据此决定内部异常是否上抛）；系统后端面则不透传。
        plugin_kwargs = {**kwargs, "raise_exception": raise_exception}
        for plugin, module_dict in PluginManager().get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method not in module_dict:
                continue
            func = module_dict[method]
            if not func:
                continue
            try:
                logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                if self._is_valid_empty(result):
                    result = func(*args, **plugin_kwargs)
                elif isinstance(result, list):
                    temp = func(*args, **plugin_kwargs)
                    if isinstance(temp, list):
                        result.extend(temp)
                else:
                    break
            except RateLimitExceededException as err:
                self._handle_rate_limit_error(err, "插件", plugin_id, method, raise_exception)
            except Exception as err:
                self._handle_plugin_error(err, plugin_id, plugin_name, method, raise_exception)
        return result

    def _dispatch_system_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """
        按优先级（get_priority 升序）依次调用各系统后端模块的同名方法，按合并规则累积结果
        （识别为管道域：当前结果可作为下一后端入参时经 check_signature 透传，逐源精化）。

        :param method: 方法名
        :param result: 已累积的结果
        :param raise_exception: 出错时是否抛出
        :return: 累积后的结果
        """
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self._modulemanager.get_running_modules(method),
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
                if self._is_valid_empty(result):
                    result = func(*args, **kwargs)
                elif ObjectUtils.check_signature(func, result):
                    result = func(result)
                elif isinstance(result, list):
                    temp = func(*args, **kwargs)
                    if isinstance(temp, list):
                        result.extend(temp)
                else:
                    break
            except RateLimitExceededException as err:
                self._handle_rate_limit_error(err, "模块", module_id, method, raise_exception)
            except Exception as err:
                logger.error(traceback.format_exc())
                self._handle_system_error(err, module_id, module_name, method, raise_exception)
        return result

    def dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        按方法名分发：先经插件注册的同名方法，得到非空且非列表的结果即返回，否则继续系统后端模块。

        合并规则：当前结果为空时取后端返回值；可作为下一后端入参时透传（管道精化）；为列表时合并各后端列表；
        为非空标量时短路返回。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（默认 False）
        :return: 各数据源合并/精化后的结果
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # 异步分发内核：异步插件钩子面 + 异步系统后端面
    # ------------------------------------------------------------------ #

    async def _async_dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                             *args, **kwargs) -> Any:
        """
        异步依次调用各已启用插件注册的同名方法（同步方法经线程池执行避免阻塞事件循环），按合并规则累积结果。

        :param method: 方法名
        :param result: 已累积的结果
        :param raise_exception: 出错时是否抛出；同时随调用透传给插件方法
        :return: 累积后的结果
        """
        import inspect
        from app.helper.plugin_manager import PluginManager
        plugin_kwargs = {**kwargs, "raise_exception": raise_exception}
        for plugin, module_dict in PluginManager().get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method not in module_dict:
                continue
            func = module_dict[method]
            if not func:
                continue
            try:
                logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
                if self._is_valid_empty(result):
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **plugin_kwargs)
                    else:
                        result = await run_in_threadpool(func, *args, **plugin_kwargs)
                elif isinstance(result, list):
                    if inspect.iscoroutinefunction(func):
                        temp = await func(*args, **plugin_kwargs)
                    else:
                        temp = await run_in_threadpool(func, *args, **plugin_kwargs)
                    if isinstance(temp, list):
                        result.extend(temp)
                else:
                    break
            except RateLimitExceededException as err:
                self._handle_rate_limit_error(err, "插件", plugin_id, method, raise_exception)
            except Exception as err:
                self._handle_plugin_error(err, plugin_id, plugin_name, method, raise_exception)
        return result

    async def _async_dispatch_system_modules(self, method: str, result: Any, raise_exception: bool,
                                             *args, **kwargs) -> Any:
        """
        异步按优先级（get_priority 升序）依次调用各系统后端模块的同名方法（同步方法经线程池执行），
        按合并规则累积结果（识别为管道域：结果可作为下一后端入参时经 check_signature 透传，逐源精化）。

        :param method: 方法名
        :param result: 已累积的结果
        :param raise_exception: 出错时是否抛出
        :return: 累积后的结果
        """
        import inspect
        logger.debug(f"请求系统模块执行：{method} ...")
        for module in sorted(
                self._modulemanager.get_running_modules(method),
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
                if self._is_valid_empty(result):
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = await run_in_threadpool(func, *args, **kwargs)
                elif ObjectUtils.check_signature(func, result):
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
                self._handle_rate_limit_error(err, "模块", module_id, method, raise_exception)
            except Exception as err:
                logger.error(traceback.format_exc())
                self._handle_system_error(err, module_id, module_name, method, raise_exception)
        return result

    async def async_dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        dispatch 的异步版本：同步的后端方法经线程池执行避免阻塞事件循环，分发与合并规则与 dispatch 一致。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（默认 False）
        :return: 各数据源合并/精化后的结果
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = await self._async_dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return await self._async_dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # IMediaRecognize 对外面：按方法名转发到 dispatch / async_dispatch。
    # ------------------------------------------------------------------ #

    def recognize_media(self, *args, **kwargs) -> Any:
        """
        识别媒体信息（跨数据源管道，逐源精化结果）。

        :param meta: 文件元数据
        :param mtype: 媒体类型
        :param tmdbid: TheMovieDb ID
        :param doubanid: 豆瓣 ID
        :param bangumiid: Bangumi ID
        :return: 识别到的媒体信息
        """
        return self.dispatch("recognize_media", *args, **kwargs)

    def search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按元数据搜索媒体信息（跨数据源合并结果）。

        :param meta: 文件元数据
        :return: 媒体信息列表
        """
        return self.dispatch("search_medias", *args, **kwargs)

    async def async_search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_medias 的异步版本。

        :param meta: 文件元数据
        :return: 媒体信息列表
        """
        return await self.async_dispatch("async_search_medias", *args, **kwargs)

    def search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按名称搜索人物（跨数据源合并结果）。

        :param name: 人物名称
        :return: 人物信息列表
        """
        return self.dispatch("search_persons", *args, **kwargs)

    async def async_search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_persons 的异步版本。

        :param name: 人物名称
        :return: 人物信息列表
        """
        return await self.async_dispatch("async_search_persons", *args, **kwargs)

    def search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        按名称搜索系列/合集（跨数据源合并结果）。

        :param name: 系列/合集名称
        :return: 媒体信息列表
        """
        return self.dispatch("search_collections", *args, **kwargs)

    async def async_search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """
        search_collections 的异步版本。

        :param name: 系列/合集名称
        :return: 媒体信息列表
        """
        return await self.async_dispatch("async_search_collections", *args, **kwargs)

    def obtain_images(self, *args, **kwargs) -> Any:
        """
        补充获取媒体图片（跨数据源精化）。

        :param mediainfo: 媒体信息
        :return: 补充图片后的媒体信息
        """
        return self.dispatch("obtain_images", *args, **kwargs)

    async def async_obtain_images(self, *args, **kwargs) -> Any:
        """
        obtain_images 的异步版本。

        :param mediainfo: 媒体信息
        :return: 补充图片后的媒体信息
        """
        return await self.async_dispatch("async_obtain_images", *args, **kwargs)
