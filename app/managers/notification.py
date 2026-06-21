import traceback
from typing import Any, Dict, Optional

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class NotificationManager(metaclass=Singleton):
    """
    消息通知（Notification 域）统一入口（单例）。

    对外提供一组通知操作方法（契约见 app.modules.INotification），按方法名分两步分发：先经各已启用插件
    注册的同名方法，再到系统通知后端模块（内建 Telegram/WeChat/Slack/Discord/VoceChat/... 及插件经
    provides_notifications() 注册的渠道）。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的渠道。

    通知为广播域：post_* 类方法返回 None、不短路，对所有启用渠道广播（各渠道内部自行按渠道/来源/类型过滤
    是否处理）；delete_message/edit_message 等返回非空值，按取首个非空短路。后端按需实现子集，按方法名分发
    自然只命中实现者。

    对外方法的参数原样转发到后端（各方法的参数见下方说明及 app.modules.INotification）。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    # ------------------------------------------------------------------ #
    # 分发内核：插件钩子面 + 系统后端面
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

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """
        依次调用各已启用插件注册的同名方法，按合并规则累积结果。

        :param method: 方法名
        :param result: 已累积的结果，用于判定空值合并 / 列表合并 / 短路
        :param raise_exception: 出错时是否抛出；同时随调用透传给插件方法
        :return: 累积后的结果
        """
        # 延迟导入，避免包初始化期的循环依赖。
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
            logger.info(f"请求插件 {plugin_name} 执行：{method} ...")
            try:
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
        按优先级（get_priority 升序）依次调用各系统后端模块的同名方法，按合并规则累积结果。

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

        合并规则（两面一致）：当前结果为空时取后端返回值；为列表时合并各后端列表；为非空标量时短路返回。
        通知为广播域——post_* 返回 None 不短路，对所有启用渠道广播。

        :param method: 要分发的方法名
        :param raise_exception: 出错时是否抛出（默认 False）
        :return: 各后端合并后的结果
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # INotification 对外面：按方法名转发到 dispatch。
    # ------------------------------------------------------------------ #

    def post_message(self, *args, **kwargs) -> None:
        """
        发送通知消息，广播到所有启用的通知渠道（各渠道内部自行过滤是否处理）。

        :param message: 通知内容（Notification）
        """
        return self.dispatch("post_message", *args, **kwargs)

    def post_medias_message(self, *args, **kwargs) -> None:
        """
        发送媒体信息选择列表，广播到所有启用渠道。

        :param message: 通知内容（Notification）
        :param medias: 媒体信息列表（List[MediaInfo]）
        """
        return self.dispatch("post_medias_message", *args, **kwargs)

    def post_torrents_message(self, *args, **kwargs) -> None:
        """
        发送种子信息选择列表，广播到所有启用渠道。

        :param message: 通知内容（Notification）
        :param torrents: 种子上下文列表（List[Context]）
        """
        return self.dispatch("post_torrents_message", *args, **kwargs)

    def delete_message(self, *args, **kwargs) -> Optional[bool]:
        """
        删除已发送的消息（取首个非空结果）。

        :param channel: 消息渠道
        :param source: 渠道来源标识
        :param message_id: 消息 ID
        :param chat_id: 会话 ID
        :return: 是否删除成功
        """
        return self.dispatch("delete_message", *args, **kwargs)

    def edit_message(self, *args, **kwargs) -> Any:
        """
        编辑已发送的消息（取首个非空结果）。

        :param channel: 消息渠道
        :param source: 渠道来源标识
        :param message_id: 消息 ID
        :param chat_id: 会话 ID
        :param text: 新正文
        :param title: 新标题
        :param buttons: 按钮列表
        :param metadata: 附加元数据
        :return: 是否编辑成功
        """
        return self.dispatch("edit_message", *args, **kwargs)

    def send_direct_message(self, *args, **kwargs) -> Any:
        """
        直接发送消息并返回渠道响应（取首个非空，不入消息队列/历史）。

        :param message: 通知内容（Notification）
        :return: 渠道响应（MessageResponse）
        """
        return self.dispatch("send_direct_message", *args, **kwargs)

    def finalize_message(self, *args, **kwargs) -> Optional[bool]:
        """
        对已发送消息执行渠道收尾动作（取首个非空）。

        :param response: 发送阶段返回的渠道响应（MessageResponse）
        :return: 是否处理成功
        """
        return self.dispatch("finalize_message", *args, **kwargs)

    def register_commands(self, commands: Dict[str, dict]) -> None:
        """
        向所有启用渠道注册菜单命令（广播）。

        :param commands: 命令定义（命令名 -> 命令配置）
        """
        return self.dispatch("register_commands", commands=commands)
