import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import DownloaderTorrent, DownloaderFile, DownloaderInfo
from app.schemas.types import EventType, TorrentStatus
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class DownloaderManager(metaclass=Singleton):
    """
    下载器（Downloader 域）门面。

    对照存储域的 FileManager：把"下载器"领域升级为"门面 + 后端"模式——对外提供一组
    类型化、可发现的统一方法（实现 app.modules.IDownloader 契约的对外面），对内按方法名分发
    到所有 ModuleType.Downloader 后端模块（内建 Qbittorrent/Transmission/Rtorrent 以及插件经
    provides_downloaders() 注册的下载器），并按与 ChainBase.run_module 完全一致的合并语义
    （列表 extend / 非列表取首个非 None）汇总结果。

    设计要点：
    - **行为等价**：_dispatch 忠实复刻 ChainBase.__execute_system_modules 的分发与合并（含
      check_signature 分支、异常逐后端续跑、SystemError 事件与消息上报），调用的是与 run_module
      同一批后端模块方法（后端方法体零改动），故对真实下载器客户端的行为不变；唯一被收敛的是
      "字符串 ABI 分发"这一隐式面，被显式、类型化的门面取代。tests/test_downloader_facade.py
      以等价性测试证明门面与 run_module 在各返回形态下结果全等。
    - **v2 兼容路径保留**：内建下载器仍作为 _ModuleBase 模块注册，ChainBase.run_module("download")
      等字符串分发仍可用（标记为 v2 兼容路径、计划后续废弃，见各下载器模块类 docstring）。门面
      不替换该路径，只作为新代码的首选入口叠加其上。
    - **后端发现**：每次分发实时查询 ModuleManager().get_running_modules(method)，自动纳入运行期
      注册/卸载的插件下载器，无需门面侧维护后端清单。

    注意：门面只复刻 run_module 的"系统模块"分发面；run_module 另有 get_module 劫持的"插件模块"
    面（__execute_plugin_modules），实测下载器域无任何插件经该面劫持（劫持集中在存储/整理域），
    故门面覆盖完整；如需该面的极端兼容场景，run_module 仍在。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """
        判断结果是否为空（与 ChainBase.__is_valid_empty 同义）：元组要求全 None，否则判 is None。
        """
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        return ret is None

    def _handle_error(self, err: Exception, module_id: str, module_name: str,
                      method: str, raise_exception: bool) -> None:
        """
        后端方法执行出错处理（复刻 ChainBase.__handle_system_error 的对外可见行为）：
        raise_exception 为真则抛出；否则记录日志 + 推送系统错误消息 + 发送 SystemError 事件后续跑。
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

    def _dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        将下载器方法按方法名分发到所有 Downloader 后端模块并合并结果。

        合并语义与 ChainBase.__execute_system_modules 严格一致：按 get_priority() 升序遍历后端，
        - 结果为空（None/全 None 元组）→ 取该后端返回值；
        - 结果与方法签名一致（check_signature，下载器方法因参数数 ≠1 恒为 False）→ 透传；
        - 结果为列表 → 合并后续后端的列表结果；
        - 否则（非空非列表，如 bool/tuple/dict）→ 短路停止。
        单后端异常逐个捕获续跑，不影响其它后端；raise_exception=True 时透传首个异常。
        """
        # pop 而非 get：raise_exception 是分发器控制位，不应透传给不接受该参数的后端 func
        # （下载器后端方法无 raise_exception 形参，透传会触发 TypeError）。
        raise_exception = bool(kwargs.pop("raise_exception", False))
        result: Any = None
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
            except Exception as err:
                self._handle_error(err, module_id, module_name, method, raise_exception)
        return result

    # ------------------------------------------------------------------ #
    # IDownloader 对外面：签名与 ChainBase 下载器包装方法一致，便于调用方平滑切换。
    # ------------------------------------------------------------------ #

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
        添加下载任务。
        :return: 下载器名称、种子Hash、种子文件布局、错误原因
        """
        return self._dispatch(
            "download",
            content=content,
            download_dir=download_dir,
            cookie=cookie,
            episodes=episodes,
            category=category,
            label=label,
            downloader=downloader,
        )

    def list_torrents(
            self,
            status: TorrentStatus = None,
            hashs: Union[list, str] = None,
            downloader: Optional[str] = None,
            include_all_tags: bool = False,
    ) -> Optional[List[DownloaderTorrent]]:
        """
        获取下载器种子列表。
        """
        return self._dispatch(
            "list_torrents",
            status=status,
            hashs=hashs,
            downloader=downloader,
            include_all_tags=include_all_tags,
        )

    def remove_torrents(
            self,
            hashs: Union[str, list],
            delete_file: bool = True,
            downloader: Optional[str] = None,
    ) -> Optional[bool]:
        """
        删除下载器种子。
        """
        return self._dispatch(
            "remove_torrents",
            hashs=hashs,
            delete_file=delete_file,
            downloader=downloader,
        )

    def start_torrents(self, hashs: Union[list, str], downloader: Optional[str] = None) -> Optional[bool]:
        """
        开始下载。
        """
        return self._dispatch("start_torrents", hashs=hashs, downloader=downloader)

    def stop_torrents(self, hashs: Union[list, str], downloader: Optional[str] = None) -> Optional[bool]:
        """
        停止下载。
        """
        return self._dispatch("stop_torrents", hashs=hashs, downloader=downloader)

    def set_torrents_tag(
            self, hashs: Union[list, str], tags: list, downloader: Optional[str] = None
    ) -> Optional[bool]:
        """
        设置种子标签。
        """
        return self._dispatch("set_torrents_tag", hashs=hashs, tags=tags, downloader=downloader)

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
        """
        return self._dispatch(
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
            self, hash_string: str, downloader: Optional[str] = None
    ) -> Optional[Dict[str, List[str]]]:
        """
        查询下载任务 Tracker 列表。
        """
        return self._dispatch("get_torrent_trackers", hash_string=hash_string, downloader=downloader)

    def torrent_files(self, tid: str, downloader: Optional[str] = None) -> Optional[List[DownloaderFile]]:
        """
        获取种子文件列表。
        """
        return self._dispatch("torrent_files", tid=tid, downloader=downloader)

    def downloader_info(self, downloader: Optional[str] = None) -> Optional[List[DownloaderInfo]]:
        """
        获取下载器统计信息。
        """
        return self._dispatch("downloader_info", downloader=downloader)

    def transfer_completed(self, hashs: str, downloader: Optional[str] = None) -> None:
        """
        下载器转移完成后的处理。
        """
        return self._dispatch("transfer_completed", hashs=hashs, downloader=downloader)
