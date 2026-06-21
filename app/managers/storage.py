import traceback
from typing import Any, Optional

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class StorageManager(metaclass=Singleton):
    """
    存储（Storage 域）统一入口（单例）。

    对外提供一组存储操作方法，按方法名分两步分发：先经各已启用插件注册的同名方法，再到系统存储后端
    （FileManagerModule，内部按存储类型 schema 路由到本地/115/U115/阿里云盘/Rclone 等具体存储后端，
    后端契约见 app.modules.filemanager.storages.StorageBase）。插件可经同名方法接入自定义存储。

    分发结果取首个非空 / 列表合并 / 非空标量短路。存储方法按 storage 名称或 fileitem 所属存储路由到对应
    后端，故各方法天然作用于单个存储。

    对外方法的参数原样转发到后端（各方法的参数见下方说明）。
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
    # 存储对外面：按方法名转发到 dispatch。
    # ------------------------------------------------------------------ #

    def save_config(self, *args, **kwargs) -> Any:
        """
        保存指定存储的配置。

        :param storage: 存储类型标识（schema）
        :param conf: 配置内容
        """
        return self.dispatch("save_config", *args, **kwargs)

    def reset_config(self, *args, **kwargs) -> Any:
        """
        重置指定存储的配置。

        :param storage: 存储类型标识（schema）
        """
        return self.dispatch("reset_config", *args, **kwargs)

    def generate_qrcode(self, *args, **kwargs) -> Optional[dict]:
        """
        生成存储登录二维码（仅支持扫码登录的存储）。

        :param storage: 存储类型标识（schema）
        :return: (二维码数据, 提示信息)
        """
        return self.dispatch("generate_qrcode", *args, **kwargs)

    def generate_auth_url(self, *args, **kwargs) -> Optional[str]:
        """
        生成 OAuth2 授权链接（仅支持 OAuth2 的存储）。

        :param storage: 存储类型标识（schema）
        :return: (授权参数, 授权链接)
        """
        return self.dispatch("generate_auth_url", *args, **kwargs)

    def check_login(self, *args, **kwargs) -> Optional[dict]:
        """
        查询存储登录状态（如扫码/授权是否完成）。

        :param storage: 存储类型标识（schema）
        :return: 登录状态信息
        """
        return self.dispatch("check_login", *args, **kwargs)

    def list_files(self, *args, **kwargs) -> Any:
        """
        浏览目录下的文件与子目录。

        :param fileitem: 目录项
        :param recursion: 是否递归列出子目录
        :return: 文件/目录项列表
        """
        return self.dispatch("list_files", *args, **kwargs)

    def any_files(self, *args, **kwargs) -> Optional[bool]:
        """
        判断目录下是否存在指定扩展名的文件。

        :param fileitem: 目录项
        :param extensions: 扩展名列表，None 表示任意文件
        :return: 是否存在
        """
        return self.dispatch("any_files", *args, **kwargs)

    def create_folder(self, *args, **kwargs) -> Any:
        """
        在指定父目录下创建子目录。

        :param fileitem: 父目录项
        :param name: 新目录名
        :return: 新建的目录项
        """
        return self.dispatch("create_folder", *args, **kwargs)

    def get_folder(self, *args, **kwargs) -> Any:
        """
        获取目录项，不存在则创建。

        :param storage: 存储类型标识（schema）
        :param path: 目录路径
        :return: 目录项
        """
        return self.dispatch("get_folder", *args, **kwargs)

    def download_file(self, *args, **kwargs) -> Any:
        """
        下载文件到本地。

        :param fileitem: 文件项
        :param path: 本地保存路径，None 表示临时目录
        :return: 本地文件路径
        """
        return self.dispatch("download_file", *args, **kwargs)

    def upload_file(self, *args, **kwargs) -> Any:
        """
        上传本地文件到指定目录。

        :param fileitem: 上传目标目录项
        :param path: 本地文件路径
        :param new_name: 上传后的文件名，None 表示沿用原名
        :return: 上传后的文件项
        """
        return self.dispatch("upload_file", *args, **kwargs)

    def delete_file(self, *args, **kwargs) -> Optional[bool]:
        """
        删除文件或目录。

        :param fileitem: 文件/目录项
        :return: 是否删除成功
        """
        return self.dispatch("delete_file", *args, **kwargs)

    def rename_file(self, *args, **kwargs) -> Optional[bool]:
        """
        重命名文件或目录。

        :param fileitem: 文件/目录项
        :param name: 新名称
        :return: 是否重命名成功
        """
        return self.dispatch("rename_file", *args, **kwargs)

    def get_file_item(self, *args, **kwargs) -> Any:
        """
        按路径获取文件或目录项。

        :param storage: 存储类型标识（schema）
        :param path: 文件/目录路径
        :return: 文件/目录项
        """
        return self.dispatch("get_file_item", *args, **kwargs)

    def get_parent_item(self, *args, **kwargs) -> Any:
        """
        获取文件/目录的父目录项。

        :param fileitem: 文件/目录项
        :return: 父目录项
        """
        return self.dispatch("get_parent_item", *args, **kwargs)

    def snapshot_storage(self, *args, **kwargs) -> Any:
        """
        对存储目录做快照（输出各层级文件信息，用于变更比对）。

        :param storage: 存储类型标识（schema）
        :param path: 快照根路径
        :param last_snapshot_time: 上次快照时间，用于增量快照
        :param max_depth: 最大递归深度
        :return: 路径 -> 文件信息 的快照字典
        """
        return self.dispatch("snapshot_storage", *args, **kwargs)

    def storage_usage(self, *args, **kwargs) -> Any:
        """
        获取存储空间使用情况。

        :param storage: 存储类型标识（schema）
        :return: 存储使用信息
        """
        return self.dispatch("storage_usage", *args, **kwargs)

    def support_transtype(self, *args, **kwargs) -> Any:
        """
        获取存储支持的整理方式（移动/复制/硬链接等）。

        :param storage: 存储类型标识（schema）
        :return: 支持的整理方式
        """
        return self.dispatch("support_transtype", *args, **kwargs)
