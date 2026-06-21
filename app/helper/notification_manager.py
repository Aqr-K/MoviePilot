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
    消息通知（Notification 域）门面。

    对照下载器门面 DownloaderManager / 媒服门面 MediaServerManager：把"通知"领域升级为"门面 + 后端"
    模式——对外提供实现 app.modules.INotification 契约的类型化统一方法，对内按方法名分发到所有通知
    后端（内建 Telegram/WeChat/Slack/Discord/... 及插件经 provides_notifications() 注册的渠道）。

    **与下载器/媒服门面的关键差异——复刻完整 run_module（插件劫持面 + 系统面）**：
    通知域历史上存在 v2 插件经 get_module() 劫持 post_message 等方法槽的用法（自定义渠道插件常见）。
    为"兼容 v2 现存插件"，本门面 dispatch 不像下载器/媒服门面那样只复刻系统模块面，而是**完整复刻
    ChainBase.run_module = __execute_plugin_modules（插件劫持面）+ __execute_system_modules（系统面）**：
    先跑插件劫持面、其返回非空且非列表则短路，否则继续系统模块面。由此门面成为 run_module 的
    byte-equivalent drop-in，可安全取代 ChainBase 中通知方法的直接 run_module 调用，零破坏 v2 劫持插件。

    **v2 兼容路径保留**：内建通知模块仍作为 _ModuleBase 模块注册，ChainBase.run_module("post_message")
    等字符串分发仍可用（标记 v2 兼容、计划后续废弃，见各通知模块类 docstring）。门面不替换该路径，
    只作为新代码的首选类型化入口叠加其上。

    注：通知是**广播域**——post_* 方法返回 None 不短路，对所有启用渠道广播（各渠道内部经 check_message
    自行过滤）；delete_message/edit_message 返回非空值，按"取首个非空"短路。后端按需实现子集，按方法名
    分发自然只命中实现者。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    # ------------------------------------------------------------------ #
    # 分发内核：忠实复刻 ChainBase.run_module（插件劫持面 + 系统模块面）
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """与 ChainBase.__is_valid_empty 同义：元组要求全 None，否则判 is None。"""
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        return ret is None

    def _handle_system_error(self, err: Exception, module_id: str, module_name: str,
                             method: str, raise_exception: bool) -> None:
        """复刻 ChainBase.__handle_system_error：raise 或 记录+系统错误消息+SystemError 事件后续跑。"""
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
        """复刻 ChainBase.__handle_plugin_error：raise 或 记录+插件错误消息(role=plugin)+SystemError 事件。"""
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
        """复刻 ChainBase.__handle_rate_limit_error：raise 或 仅 INFO（限流是预期态，不触发系统告警）。"""
        if raise_exception:
            raise err
        logger.info(f"{owner} {ident}.{method} 已限流，跳过执行：{str(err)}")

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """复刻 ChainBase.__execute_plugin_modules：跑插件经 get_module 劫持的同名方法槽。"""
        # lazy import 防 import 期环（plugin_manager 依赖较重）；插件面与系统面共用 result 累积语义。
        from app.helper.plugin_manager import PluginManager
        for plugin, module_dict in PluginManager().get_plugin_modules().items():
            plugin_id, plugin_name = plugin
            if method not in module_dict:
                continue
            func = module_dict[method]
            if not func:
                continue
            try:
                if self._is_valid_empty(result):
                    result = func(*args, **kwargs)
                elif isinstance(result, list):
                    temp = func(*args, **kwargs)
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
        """复刻 ChainBase.__execute_system_modules：按 get_priority 升序跑系统通知模块、合并结果。"""
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
                self._handle_system_error(err, module_id, module_name, method, raise_exception)
        return result

    def dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        通知方法分发（run_module 的 byte-equivalent drop-in）：先插件劫持面，其返回非空且非列表即短路，
        否则继续系统模块面。raise_exception 为分发器控制位（pop 不透传给后端 func，与下载器门面一致）。
        """
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # INotification 对外面：按方法名转发到 dispatch，便于调用方平滑切换。
    # ------------------------------------------------------------------ #

    def post_message(self, *args, **kwargs) -> None:
        """发送消息（广播到所有启用渠道）。"""
        return self.dispatch("post_message", *args, **kwargs)

    def post_medias_message(self, *args, **kwargs) -> None:
        """发送媒体信息选择列表。"""
        return self.dispatch("post_medias_message", *args, **kwargs)

    def post_torrents_message(self, *args, **kwargs) -> None:
        """发送种子信息选择列表。"""
        return self.dispatch("post_torrents_message", *args, **kwargs)

    def delete_message(self, *args, **kwargs) -> Optional[bool]:
        """删除消息（取首个非空结果）。"""
        return self.dispatch("delete_message", *args, **kwargs)

    def edit_message(self, *args, **kwargs) -> Any:
        """编辑消息（取首个非空结果）。"""
        return self.dispatch("edit_message", *args, **kwargs)

    def send_direct_message(self, *args, **kwargs) -> Any:
        """直接发送消息并返回响应（取首个非空，不经消息队列/历史）。"""
        return self.dispatch("send_direct_message", *args, **kwargs)

    def finalize_message(self, *args, **kwargs) -> Optional[bool]:
        """对已发送消息执行渠道收尾动作（取首个非空）。"""
        return self.dispatch("finalize_message", *args, **kwargs)

    def register_commands(self, commands: Dict[str, dict]) -> None:
        """向所有渠道注册菜单命令（广播）。"""
        return self.dispatch("register_commands", commands=commands)
