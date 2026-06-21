import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import DownloaderTorrent, DownloaderFile, DownloaderInfo
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType, TorrentStatus
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class DownloaderManager(metaclass=Singleton):
    """
    下载器（Downloader 域）统一入口（单例）。

    对外提供一组类型化的下载器操作方法（契约见 app.modules.IDownloader），按方法名分发到所有已启用的
    下载器后端模块（内建 Qbittorrent/Transmission/Rtorrent 及插件经 provides_downloaders() 注册的下载器），
    并合并各后端结果。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的插件下载器，无需维护清单。

    约定：凡接受 downloader 形参的方法，传 None 时面向全部下载器，传具体名称时只作用于该下载器。
    """

    def __init__(self):
        self._modulemanager = ModuleManager()
        self._messagehelper = MessageHelper()

    @staticmethod
    def _is_valid_empty(ret: Any) -> bool:
        """判断分发结果是否为空：元组需全部为 None，其余按 is None 判断。"""
        if isinstance(ret, tuple):
            return all(value is None for value in ret)
        return ret is None

    def _handle_error(self, err: Exception, module_id: str, module_name: str,
                      method: str, raise_exception: bool) -> None:
        """
        后端方法执行出错的处理。

        :param err: 捕获到的异常
        :param module_id: 后端类名
        :param module_name: 后端显示名
        :param method: 出错的方法名
        :param raise_exception: 为真时直接抛出；否则记录错误日志、推送系统错误消息、广播 SystemError 事件后继续下一个后端
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
    def _handle_rate_limit_error(err: RateLimitExceededException, module_id: str,
                                 method: str, raise_exception: bool) -> None:
        """
        后端触发限流时的处理：raise_exception 为真时直接抛出；否则仅记录 INFO 并跳过该后端
        （限流为预期状态，不作系统告警）。
        """
        if raise_exception:
            raise err
        logger.info(f"模块 {module_id}.{method} 已限流，跳过执行：{str(err)}")

    def _dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        按方法名分发到所有下载器后端模块并合并结果。

        按优先级（get_priority 升序）遍历后端：
        - 当前结果为空（None / 全 None 元组）→ 取该后端返回值；
        - 当前结果可作为下一后端的入参（check_signature，下载器方法因参数数 ≠1 恒为否）→ 透传；
        - 当前结果为列表 → 合并各后端的列表结果；
        - 当前结果为非空标量（bool/tuple/dict 等）→ 短路停止。
        单个后端异常被隔离后继续其余后端；raise_exception=True 时透传首个异常。

        :param method: 要分发的下载器方法名
        :param raise_exception: 出错时是否抛出（分发控制位，不透传给后端方法）
        :return: 各后端合并后的结果
        """
        # raise_exception 为分发控制位，pop 出后不随调用透传给后端方法（后端方法无此形参，透传会 TypeError）。
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
            except RateLimitExceededException as err:
                # 限流先于通用异常捕获：安静跳过、不告警。
                self._handle_rate_limit_error(err, module_id, method, raise_exception)
            except Exception as err:
                self._handle_error(err, module_id, module_name, method, raise_exception)
        return result

    # ------------------------------------------------------------------ #
    # IDownloader 对外面：按方法名转发到 _dispatch。
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

        :param content: 种子文件路径 / 种子链接 / 种子内容
        :param download_dir: 下载保存目录
        :param cookie: 站点 Cookie（私有种子下载用）
        :param episodes: 需要下载的集数集合（为空表示全部）
        :param category: 下载分类
        :param label: 附加标签
        :param downloader: 指定下载器名称，None 表示使用默认下载器
        :return: (下载器名称, 种子 Hash, 种子文件布局, 错误原因)
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

        :param status: 按种子状态过滤
        :param hashs: 按种子 Hash（单个或列表）过滤
        :param downloader: 指定下载器名称，None 表示全部下载器
        :param include_all_tags: 是否包含全部标签的种子
        :return: 种子信息列表
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

        :param hashs: 要删除的种子 Hash（单个或列表）
        :param delete_file: 是否同时删除文件
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 是否删除成功
        """
        return self._dispatch(
            "remove_torrents",
            hashs=hashs,
            delete_file=delete_file,
            downloader=downloader,
        )

    def start_torrents(self, hashs: Union[list, str], downloader: Optional[str] = None) -> Optional[bool]:
        """
        开始下载（恢复）指定种子。

        :param hashs: 种子 Hash（单个或列表）
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 是否操作成功
        """
        return self._dispatch("start_torrents", hashs=hashs, downloader=downloader)

    def stop_torrents(self, hashs: Union[list, str], downloader: Optional[str] = None) -> Optional[bool]:
        """
        停止（暂停）指定种子。

        :param hashs: 种子 Hash（单个或列表）
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 是否操作成功
        """
        return self._dispatch("stop_torrents", hashs=hashs, downloader=downloader)

    def set_torrents_tag(
            self, hashs: Union[list, str], tags: list, downloader: Optional[str] = None
    ) -> Optional[bool]:
        """
        设置种子标签。

        :param hashs: 种子 Hash（单个或列表）
        :param tags: 要设置的标签列表
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 是否操作成功
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
        修改下载任务属性（仅传入的字段生效）。

        :param hash_string: 种子 Hash
        :param downloader: 指定下载器名称，None 表示全部下载器
        :param download_limit: 下载限速
        :param upload_limit: 上传限速
        :param tracker_list: Tracker 列表
        :param save_path: 保存路径
        :param category: 分类
        :param ratio_limit: 分享率限制
        :param seeding_time_limit: 做种时间限制
        :return: 各项修改是否成功
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
        查询下载任务的 Tracker 列表。

        :param hash_string: 种子 Hash
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: Tracker 信息（按下载任务归类）
        """
        return self._dispatch("get_torrent_trackers", hash_string=hash_string, downloader=downloader)

    def torrent_files(self, tid: str, downloader: Optional[str] = None) -> Optional[List[DownloaderFile]]:
        """
        获取种子的文件列表。

        :param tid: 种子 Hash
        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 种子文件列表
        """
        return self._dispatch("torrent_files", tid=tid, downloader=downloader)

    def downloader_info(self, downloader: Optional[str] = None) -> Optional[List[DownloaderInfo]]:
        """
        获取下载器实时统计信息（速率、连接等）。

        :param downloader: 指定下载器名称，None 表示全部下载器
        :return: 下载器统计信息列表
        """
        return self._dispatch("downloader_info", downloader=downloader)

    def transfer_completed(self, hashs: str, downloader: Optional[str] = None) -> None:
        """
        整理完成后对种子执行的收尾处理（如打标签）。

        :param hashs: 种子 Hash
        :param downloader: 指定下载器名称，None 表示全部下载器
        """
        return self._dispatch("transfer_completed", hashs=hashs, downloader=downloader)
