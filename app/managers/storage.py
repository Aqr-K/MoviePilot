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
    存储（Storage 域）门面。

    补齐储存域的「三层」末层：储存域的**契约层已是 StorageBase**（16 abstractmethod，全仓最成熟范式）、
    **注册层已是 storage_registry**（按 schema.value 单索引），但其「门面」角色历史上被**揉进了
    FileManagerModule 这个 _ModuleBase 模块**里——FileManagerModule 既是被 ModuleManager 扫描的模块、
    又承担按 schema 路由到 storages/ 后端的聚合。本门面把「门面」从模块中**显式抽出**，与下载器
    DownloaderManager / 媒服 MediaServerManager / 通知 NotificationManager / 识别 MediaRecognizeManager
    对齐：StorageChain 直接调本门面，取代 `StorageChain.run_module(...) → 唯一 FileManagerModule` 这层
    **仪式性的字符串 ABI 双层派发**。

    派发结构：储存域只有一个系统模块 FileManagerModule（schema 路由在其内部完成），故本门面按方法名
    分发自然命中它；**复刻完整 run_module（插件劫持面 + 系统面）** ——储存/整理域是 v2 插件经 get_module()
    劫持方法槽的重灾区（如 p115 接入 115 储存），唯有完整复刻才能在改接后零破坏这些劫持插件。dispatch
    成为 run_module 的 byte-equivalent drop-in。

    **v2 兼容路径保留**：FileManagerModule 仍作为 _ModuleBase 模块注册，StorageChain/ChainBase 的
    run_module 字符串分发仍可用（标 v2 兼容、计划后续废弃）；schema 路由、storage_registry、StorageBase
    后端零改动。门面只取代外层字符串派发、不动内层 schema 路由。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

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

    def _dispatch_plugin_modules(self, method: str, result: Any, raise_exception: bool,
                                 *args, **kwargs) -> Any:
        """复刻 ChainBase.__execute_plugin_modules（储存/整理域 get_module 劫持重灾区）。"""
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
        """复刻 ChainBase.__execute_system_modules（储存域系统模块=FileManagerModule，schema 路由在其内部）。"""
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
        """储存方法分发（run_module 的 byte-equivalent drop-in）：先插件劫持面、非空非列表短路、再系统面。"""
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
        result = self._dispatch_plugin_modules(method, result, raise_exception, *args, **kwargs)
        if not self._is_valid_empty(result) and not isinstance(result, list):
            return result
        return self._dispatch_system_modules(method, result, raise_exception, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # 储存对外面：与 StorageChain 包装方法 / FileManagerModule 方法同名，按方法名转发到 dispatch。
    # ------------------------------------------------------------------ #

    def save_config(self, *args, **kwargs) -> Any:
        """保存存储配置。"""
        return self.dispatch("save_config", *args, **kwargs)

    def reset_config(self, *args, **kwargs) -> Any:
        """重置存储配置。"""
        return self.dispatch("reset_config", *args, **kwargs)

    def generate_qrcode(self, *args, **kwargs) -> Optional[dict]:
        """生成登录二维码。"""
        return self.dispatch("generate_qrcode", *args, **kwargs)

    def generate_auth_url(self, *args, **kwargs) -> Optional[str]:
        """生成授权链接。"""
        return self.dispatch("generate_auth_url", *args, **kwargs)

    def check_login(self, *args, **kwargs) -> Optional[dict]:
        """检查登录状态。"""
        return self.dispatch("check_login", *args, **kwargs)

    def list_files(self, *args, **kwargs) -> Any:
        """浏览目录文件。"""
        return self.dispatch("list_files", *args, **kwargs)

    def any_files(self, *args, **kwargs) -> Optional[bool]:
        """判断目录下是否存在指定扩展名的文件。"""
        return self.dispatch("any_files", *args, **kwargs)

    def create_folder(self, *args, **kwargs) -> Any:
        """创建目录。"""
        return self.dispatch("create_folder", *args, **kwargs)

    def get_folder(self, *args, **kwargs) -> Any:
        """获取目录（不存在则创建）。"""
        return self.dispatch("get_folder", *args, **kwargs)

    def download_file(self, *args, **kwargs) -> Any:
        """下载文件。"""
        return self.dispatch("download_file", *args, **kwargs)

    def upload_file(self, *args, **kwargs) -> Any:
        """上传文件。"""
        return self.dispatch("upload_file", *args, **kwargs)

    def delete_file(self, *args, **kwargs) -> Optional[bool]:
        """删除文件/目录。"""
        return self.dispatch("delete_file", *args, **kwargs)

    def rename_file(self, *args, **kwargs) -> Optional[bool]:
        """重命名文件/目录。"""
        return self.dispatch("rename_file", *args, **kwargs)

    def get_file_item(self, *args, **kwargs) -> Any:
        """按路径获取文件项。"""
        return self.dispatch("get_file_item", *args, **kwargs)

    def get_parent_item(self, *args, **kwargs) -> Any:
        """获取父目录项。"""
        return self.dispatch("get_parent_item", *args, **kwargs)

    def snapshot_storage(self, *args, **kwargs) -> Any:
        """存储快照。"""
        return self.dispatch("snapshot_storage", *args, **kwargs)

    def storage_usage(self, *args, **kwargs) -> Any:
        """存储使用情况。"""
        return self.dispatch("storage_usage", *args, **kwargs)

    def support_transtype(self, *args, **kwargs) -> Any:
        """存储支持的整理方式。"""
        return self.dispatch("support_transtype", *args, **kwargs)
