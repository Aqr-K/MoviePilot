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
    媒体识别 / 数据源（MediaRecognize 域）门面。

    对照下载器 DownloaderManager / 媒服 MediaServerManager / 通知 NotificationManager：把"识别/数据源"
    领域升级为"门面 + 后端"模式——对外提供实现 app.modules.IMediaRecognize 契约的类型化统一方法，对内
    按方法名分发到所有数据源后端（内建 TheMovieDb/Douban/Bangumi/TheTvDb 及插件经 provides_data_sources()
    注册的源）。

    **派发语义——管道（pipeline）**：识别是跨源管道域，`recognize_media` 等方法的返回值在源之间**流转**
    （`check_signature` 分支：上一源的非空结果与下一源方法签名一致时作为入参传入，逐源精化）；search_*
    等列表方法跨源 extend 合并；首个非空非列表结果短路。这与通知（广播）、下载器（取首个非空）不同，
    但**统一由复刻 run_module 的 dispatch 内核表达**（is_valid_empty / check_signature / list extend / break
    四分支正是管道语义的载体）。

    **复刻完整 run_module（插件劫持面 + 系统面）以兼容 v2 现存插件**：识别域历史上存在 v2 插件经
    get_module() 劫持 recognize_media 等方法槽以接入自定义识别源。为兼容这些插件，dispatch/async_dispatch
    **完整复刻** ChainBase.run_module / async_run_module = 插件劫持面 + 系统面，成为其 byte-equivalent
    drop-in。**v2 兼容路径保留**：内建数据源仍作为 _ModuleBase 模块注册，run_module 字符串分发仍可用
    （标 v2 兼容、计划后续废弃）。门面只作为新代码的首选类型化入口叠加其上。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    # ------------------------------------------------------------------ #
    # 错误/空值处理（与 ChainBase 对外可见行为一致）
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """与 ChainBase.__is_valid_empty 同义：元组要求全 None，否则判 is None。"""
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        return ret is None

    def _handle_system_error(self, err: Exception, module_id: str, module_name: str,
                             method: str, raise_exception: bool) -> None:
        """复刻 ChainBase.__handle_system_error。"""
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
        """复刻 ChainBase.__handle_plugin_error。"""
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
        """复刻 ChainBase.__handle_rate_limit_error：raise 或 仅 INFO。"""
        if raise_exception:
            raise err
        logger.info(f"{owner} {ident}.{method} 已限流，跳过执行：{str(err)}")

    # ------------------------------------------------------------------ #
    # 同步分发内核：复刻 ChainBase.run_module（插件劫持面 + 系统面）
    # ------------------------------------------------------------------ #

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """复刻 ChainBase.__execute_plugin_modules。"""
        from app.helper.plugin_manager import PluginManager
        # 插件劫持面与 run_module 一致：raise_exception 透传给插件 func；系统面沿用 pop 语义。
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
        """复刻 ChainBase.__execute_system_modules：管道语义的载体（check_signature 透传结果）。"""
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
        """识别方法分发（run_module 的 byte-equivalent drop-in）：先插件劫持面、非空非列表短路、再系统面。"""
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # 异步分发内核：复刻 ChainBase.async_run_module（异步插件面 + 异步系统面）
    # ------------------------------------------------------------------ #

    async def _async_dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                             *args, **kwargs) -> Any:
        """复刻 ChainBase.__async_execute_plugin_modules（同步插件 func 经线程池避免阻塞事件循环）。"""
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
        """复刻 ChainBase.__async_execute_system_modules（同步系统模块经线程池）。"""
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
        """识别方法异步分发（async_run_module 的 byte-equivalent drop-in）。"""
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
        """识别媒体信息（跨源管道，逐源精化）。"""
        return self.dispatch("recognize_media", *args, **kwargs)

    def search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """搜索媒体信息（跨源 extend 合并）。"""
        return self.dispatch("search_medias", *args, **kwargs)

    async def async_search_medias(self, *args, **kwargs) -> Optional[List[Any]]:
        """异步搜索媒体信息。"""
        return await self.async_dispatch("async_search_medias", *args, **kwargs)

    def search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """搜索人物。"""
        return self.dispatch("search_persons", *args, **kwargs)

    async def async_search_persons(self, *args, **kwargs) -> Optional[List[Any]]:
        """异步搜索人物。"""
        return await self.async_dispatch("async_search_persons", *args, **kwargs)

    def search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """搜索系列/合集。"""
        return self.dispatch("search_collections", *args, **kwargs)

    async def async_search_collections(self, *args, **kwargs) -> Optional[List[Any]]:
        """异步搜索系列/合集。"""
        return await self.async_dispatch("async_search_collections", *args, **kwargs)

    def obtain_images(self, *args, **kwargs) -> Any:
        """补充获取媒体图片（跨源精化）。"""
        return self.dispatch("obtain_images", *args, **kwargs)

    async def async_obtain_images(self, *args, **kwargs) -> Any:
        """异步补充获取媒体图片。"""
        return await self.async_dispatch("async_obtain_images", *args, **kwargs)
