import traceback
from typing import Any

from app.core import dispatch
from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType
from app.utils.singleton import Singleton


class ManagerBase(metaclass=Singleton):
    """
    门面管理器基类（单例）：集中「分发内核」的共享部分——空值判定、系统/限流错误处理、系统后端面分发，
    以及仅面向系统后端的单步分发入口 _dispatch。

    门面管理器（Managers）按方法名把领域操作分发到各后端模块，被 ChainBase 直接调用。各域门面
    （downloader/mediaserver/notification/storage/mediarecognize）的遍历/合并/隔离逻辑统一收敛到
    app.core.dispatch；本基类与子类只构造后端三元组与错误回调后委托内核。

    合并规则（各域一致）：当前结果为空（None / 全 None 元组）取后端返回值；可作为下一后端入参时经
    check_signature 透传（管道域逐源精化）；为列表时跨后端 extend；为非空标量时短路停止。

    分发域差异：
    - downloader、mediaserver：仅系统后端面（插件下载器/媒服经 provides_* 注册为运行模块，已纳入
      get_running_modules），用单步 _dispatch；
    - notification、storage、mediarecognize：插件钩子面 + 系统后端面两步，用 dispatch（PluginDispatchManager）。

    单例：基类持有 Singleton 元类，各子类按 Singleton（按类与构造参数）各自独立单例；基类自身不被实例化。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    # ------------------------------------------------------------------ #
    # 空值 / 错误 / 限流 处理
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """判断分发结果是否为空：元组需全部为 None，其余按 is None 判断。"""
        return dispatch.is_valid_empty(ret)

    def _handle_system_error(self, err: Exception, module_id: str, module_name: str,
                             method: str, raise_exception: bool) -> None:
        """
        系统后端方法执行出错的处理。

        :param err: 捕获到的异常
        :param module_id: 后端类名
        :param module_name: 后端显示名
        :param method: 出错的方法名
        :param raise_exception: 为真时直接抛出；否则记录错误日志、推送系统错误消息（role=system）、
            广播 SystemError 事件后继续下一个后端
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

    @staticmethod
    def _handle_rate_limit_error(err: RateLimitExceededException, owner: str, ident: str,
                                 method: str, raise_exception: bool) -> None:
        """
        触发限流时的处理：raise_exception 为真时直接抛出；否则仅记录 INFO 并跳过该后端
        （限流为预期状态，不作系统告警）。

        :param owner: 来源类别（如 "模块" / "插件"）
        :param ident: 来源标识（后端类名 / 插件 id）
        """
        if raise_exception:
            raise err
        logger.info(f"{owner} {ident}.{method} 已限流，跳过执行：{str(err)}")

    # ------------------------------------------------------------------ #
    # 系统后端面（同步）
    # ------------------------------------------------------------------ #

    def _system_entries(self, method: str):
        """
        生成系统后端面的后端三元组 (module_id, module_name, func)：按优先级（get_priority 升序）取各运行模块的同名方法。
        """
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
            yield module_id, module_name, getattr(module, method)

    def _dispatch_system_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """
        按优先级依次调用各系统后端模块的同名方法，按合并规则累积结果（启用 check_signature 管道精化）。

        单个后端异常被隔离后继续其余后端；限流安静跳过；raise_exception=True 时透传首个异常。
        系统后端方法无 raise_exception 形参，故 kwargs 不携带该控制位。

        :param method: 方法名
        :param result: 已累积的结果（单步分发传 None）
        :param raise_exception: 出错时是否抛出
        :return: 累积后的结果
        """
        logger.debug(f"请求系统模块执行：{method} ...")
        return dispatch.execute_modules(
            self._system_entries(method), method, result, *args,
            pipeline=True,
            on_rate_limit=lambda err, ident, name, m: self._handle_rate_limit_error(
                err, "模块", ident, m, raise_exception
            ),
            on_error=lambda err, ident, name, m: self._handle_system_error(
                err, ident, name, m, raise_exception
            ),
            **kwargs,
        )

    # ------------------------------------------------------------------ #
    # 单步分发（仅系统后端面）：downloader / mediaserver 域
    # ------------------------------------------------------------------ #

    def _dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        单面分发：仅经系统后端模块（无插件钩子面）。用于插件后端已注册为运行模块的域（downloader/mediaserver）。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（分发控制位，pop 出后不随调用透传给后端方法）
        :return: 各后端合并后的结果
        """
        # raise_exception 为分发控制位，pop 出后不随调用透传给后端方法（后端方法无此形参，透传会 TypeError）。
        raise_exception = bool(kwargs.pop("raise_exception", False))
        return self._dispatch_system_modules(method, None, raise_exception, *args, **kwargs)


class PluginDispatchManager(ManagerBase):
    """
    带「插件钩子面」的门面管理器基类：在系统后端面之前，先经各已启用插件经 get_module 注册的同名方法
    分发（兼容 v2 经 get_module 劫持方法槽的现存插件）。用于 notification / storage / mediarecognize 域。

    两步分发（dispatch）：先插件钩子面，得到非空且非列表的结果即短路返回，否则把累积结果交由系统后端面继续。
    """

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

    def _plugin_entries(self, method: str):
        """
        生成插件钩子面的后端三元组 (plugin_id, plugin_name, func)：取各已启用插件注册的同名方法。
        """
        # 延迟导入，避免包初始化期的循环依赖（同时是测试的 patch 目标）。
        from app.helper.plugin_manager import PluginManager
        for plugin, module_dict in PluginManager().get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method not in module_dict:
                continue
            func = module_dict[method]
            if not func:
                continue
            yield plugin_id, plugin_name, func

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """
        依次调用各已启用插件注册的同名方法，按合并规则累积结果（不做 check_signature 精化）。

        raise_exception 随调用透传给插件方法（插件可据此决定内部异常是否上抛）；系统后端面则不透传。

        :param method: 方法名
        :param result: 已累积的结果，用于判定空值合并 / 列表合并 / 短路
        :param raise_exception: 出错时是否抛出；同时随调用透传给插件方法
        :return: 累积后的结果
        """
        plugin_kwargs = {**kwargs, "raise_exception": raise_exception}
        return dispatch.execute_modules(
            self._plugin_entries(method), method, result, *args,
            pipeline=False,
            log_each=lambda name, m: logger.info(f"请求插件 {name} 执行：{m} ..."),
            on_rate_limit=lambda err, ident, name, m: self._handle_rate_limit_error(
                err, "插件", ident, m, raise_exception
            ),
            on_error=lambda err, ident, name, m: self._handle_plugin_error(
                err, ident, name, m, raise_exception
            ),
            **plugin_kwargs,
        )

    def dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        两步分发：先经插件注册的同名方法，得到非空且非列表的结果即返回，否则继续系统后端模块。

        合并规则（两面一致）：当前结果为空时取后端返回值；可作为下一后端入参时透传（管道精化）；
        为列表时合并各后端列表；为非空标量时短路返回。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（默认 False）
        :param system_only: 为真时跳过插件钩子面，仅经系统后端模块（分发控制位，不透传给后端方法）
        :return: 各后端合并后的结果
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        system_only = bool(kwargs.pop("system_only", False))
        result: Any = None
        if not system_only:
            result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
            if not self._is_valid_empty(result) and not isinstance(result, list):
                return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)


class AsyncDispatchMixin:
    """
    异步分发混入：为门面提供 async_dispatch（dispatch 的异步版本）。同步后端方法经线程池执行，避免阻塞
    事件循环；分发与合并规则与同步 dispatch 完全一致。仅 mediarecognize 域用到（与 PluginDispatchManager
    一并继承）。

    依赖宿主类（PluginDispatchManager/ManagerBase）提供的：_is_valid_empty、_handle_rate_limit_error、
    _handle_plugin_error、_handle_system_error、_plugin_entries、_system_entries。
    """

    async def _async_dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                             *args, **kwargs) -> Any:
        """
        异步依次调用各已启用插件注册的同名方法（同步方法经线程池执行避免阻塞事件循环），按合并规则累积结果。

        :param method: 方法名
        :param result: 已累积的结果
        :param raise_exception: 出错时是否抛出；同时随调用透传给插件方法
        :return: 累积后的结果
        """
        plugin_kwargs = {**kwargs, "raise_exception": raise_exception}
        return await dispatch.async_execute_modules(
            self._plugin_entries(method), method, result, *args,
            pipeline=False,
            log_each=lambda name, m: logger.info(f"请求插件 {name} 执行：{m} ..."),
            on_rate_limit=lambda err, ident, name, m: self._handle_rate_limit_error(
                err, "插件", ident, m, raise_exception
            ),
            on_error=lambda err, ident, name, m: self._handle_plugin_error(
                err, ident, name, m, raise_exception
            ),
            **plugin_kwargs,
        )

    async def _async_dispatch_system_modules(self, method: str, result: Any, raise_exception: bool,
                                             *args, **kwargs) -> Any:
        """
        异步按优先级依次调用各系统后端模块的同名方法（同步方法经线程池执行），按合并规则累积结果
        （管道域：结果可作为下一后端入参时经 check_signature 透传，逐源精化）。系统后端方法无
        raise_exception 形参，故 kwargs 不携带该控制位。

        :param method: 方法名
        :param result: 已累积的结果
        :param raise_exception: 出错时是否抛出
        :return: 累积后的结果
        """
        logger.debug(f"请求系统模块执行：{method} ...")
        return await dispatch.async_execute_modules(
            self._system_entries(method), method, result, *args,
            pipeline=True,
            on_rate_limit=lambda err, ident, name, m: self._handle_rate_limit_error(
                err, "模块", ident, m, raise_exception
            ),
            on_error=lambda err, ident, name, m: self._handle_system_error(
                err, ident, name, m, raise_exception
            ),
            **kwargs,
        )

    async def async_dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        dispatch 的异步版本：同步的后端方法经线程池执行避免阻塞事件循环，分发与合并规则与 dispatch 一致。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（默认 False）
        :param system_only: 为真时跳过插件钩子面，仅经系统后端模块（分发控制位，不透传给后端方法）
        :return: 各后端合并/精化后的结果
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        system_only = bool(kwargs.pop("system_only", False))
        result: Any = None
        if not system_only:
            result = await self._async_dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
            if not self._is_valid_empty(result) and not isinstance(result, list):
                return result
        return await self._async_dispatch_system_modules(method, result, raise_exception, *args, **kwargs)
