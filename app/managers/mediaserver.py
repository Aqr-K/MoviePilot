import traceback
from typing import Any, Generator, List, Optional, Union, TYPE_CHECKING

from app.core.event import eventmanager
from app.core.module import ModuleManager
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import (ExistMediaInfo, MediaServerItem, MediaServerLibrary,
                         MediaServerPlayItem, MediaServerSeasonInfo, Statistic)
from app.schemas.exception import RateLimitExceededException
from app.schemas.types import EventType
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton

if TYPE_CHECKING:
    from app.core.context import MediaInfo


class MediaServerManager(metaclass=Singleton):
    """
    媒体服务器（MediaServer 域）统一入口（单例）。

    对外提供一组类型化的媒体服务器操作方法（契约见 app.modules.IMediaServer），按方法名分发到所有已启用的
    媒体服务器后端模块（内建 Emby/Jellyfin/Plex/TrimeMedia/Ugreen/ZSpace 及插件经 provides_mediaservers()
    注册的媒体服务器），并合并各后端结果。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的插件。

    约定：凡接受 server 形参的方法，传 None 时面向全部媒体服务器，传具体名称时只作用于该服务器。
    各后端 server 必填性 / username 形参存在差异，对外统一为最宽松签名并按关键字分发，对全部后端兼容。
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
        按方法名分发到所有媒体服务器后端模块并合并结果。

        按优先级（get_priority 升序）遍历后端：
        - 当前结果为空（None / 全 None 元组）→ 取该后端返回值；
        - 当前结果可作为下一后端的入参（check_signature）→ 透传；
        - 当前结果为列表 → 合并各后端的列表结果；
        - 当前结果为非空标量（str/dict/生成器等）→ 短路停止。
        单个后端异常被隔离后继续其余后端；raise_exception=True 时透传首个异常。

        :param method: 要分发的媒体服务器方法名
        :param raise_exception: 出错时是否抛出（分发控制位，不透传给后端方法）
        :return: 各后端合并后的结果
        """
        # raise_exception 为分发控制位，pop 出后不随调用透传给后端方法。
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
    # IMediaServer 对外面：按方法名转发到 _dispatch。
    # ------------------------------------------------------------------ #

    def media_exists(self, mediainfo: "MediaInfo", itemid: Optional[str] = None,
                     server: Optional[str] = None) -> Optional[ExistMediaInfo]:
        """
        判断媒体是否已存在于媒体服务器。

        :param mediainfo: 媒体信息
        :param itemid: 媒体服务器中的项目 ID（已知时可直接定位）
        :param server: 指定媒体服务器名称，None 表示全部
        :return: 已存在媒体的信息（不存在为 None）
        """
        return self._dispatch("media_exists", mediainfo=mediainfo, itemid=itemid, server=server)

    def media_statistic(self, server: Optional[str] = None) -> Optional[List[Statistic]]:
        """
        媒体数量统计（电影/剧集/用户数等）。

        :param server: 指定媒体服务器名称，None 表示全部
        :return: 各媒体服务器的统计信息列表
        """
        return self._dispatch("media_statistic", server=server)

    def mediaserver_librarys(self, server: Optional[str] = None, username: Optional[str] = None,
                             hidden: Optional[bool] = False) -> Optional[List[MediaServerLibrary]]:
        """
        获取媒体服务器的媒体库列表。

        :param server: 指定媒体服务器名称，None 表示全部
        :param username: 按用户名过滤可见媒体库
        :param hidden: 是否包含隐藏媒体库
        :return: 媒体库列表
        """
        return self._dispatch("mediaserver_librarys", server=server, username=username, hidden=hidden)

    def mediaserver_items(self, server: Optional[str] = None, library_id: Union[str, int] = None,
                          start_index: Optional[int] = 0, limit: Optional[int] = -1) -> Optional[Generator]:
        """
        获取媒体库内的项目（以生成器逐项产出）。

        :param server: 指定媒体服务器名称，None 表示全部
        :param library_id: 媒体库 ID
        :param start_index: 起始位置
        :param limit: 数量上限，-1 表示不限制
        :return: 媒体项目生成器
        """
        return self._dispatch("mediaserver_items", server=server, library_id=library_id,
                              start_index=start_index, limit=limit)

    def mediaserver_iteminfo(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> Optional[MediaServerItem]:
        """
        获取单个媒体项目的详细信息。

        :param server: 指定媒体服务器名称，None 表示全部
        :param item_id: 项目 ID
        :return: 媒体项目信息
        """
        return self._dispatch("mediaserver_iteminfo", server=server, item_id=item_id)

    def mediaserver_tv_episodes(self, server: Optional[str] = None,
                                item_id: Union[str, int] = None) -> Optional[List[MediaServerSeasonInfo]]:
        """
        获取剧集的季/集信息。

        :param server: 指定媒体服务器名称，None 表示全部
        :param item_id: 剧集项目 ID
        :return: 各季的集信息列表
        """
        return self._dispatch("mediaserver_tv_episodes", server=server, item_id=item_id)

    def mediaserver_playing(self, server: Optional[str] = None, count: Optional[int] = 20,
                            username: Optional[str] = None) -> List[MediaServerPlayItem]:
        """
        获取正在播放的项目。

        :param server: 指定媒体服务器名称，None 表示全部
        :param count: 返回数量上限
        :param username: 按用户名过滤
        :return: 正在播放的项目列表
        """
        return self._dispatch("mediaserver_playing", server=server, count=count, username=username)

    def mediaserver_play_url(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> Optional[str]:
        """
        获取项目的播放地址。

        :param server: 指定媒体服务器名称，None 表示全部
        :param item_id: 项目 ID
        :return: 播放地址
        """
        return self._dispatch("mediaserver_play_url", server=server, item_id=item_id)

    def mediaserver_latest(self, server: Optional[str] = None, count: Optional[int] = 20,
                           username: Optional[str] = None) -> List[MediaServerPlayItem]:
        """
        获取最新入库的项目。

        :param server: 指定媒体服务器名称，None 表示全部
        :param count: 返回数量上限
        :param username: 按用户名过滤
        :return: 最新入库的项目列表
        """
        return self._dispatch("mediaserver_latest", server=server, count=count, username=username)

    def mediaserver_latest_images(self, server: Optional[str] = None, count: Optional[int] = 10,
                                  username: Optional[str] = None,
                                  remote: Optional[bool] = False) -> List[str]:
        """
        获取最新入库项目的海报图片地址（用作壁纸）。

        :param server: 指定媒体服务器名称，None 表示全部
        :param count: 返回数量上限
        :param username: 按用户名过滤
        :param remote: 是否返回可远程访问的地址
        :return: 海报图片地址列表
        """
        return self._dispatch("mediaserver_latest_images", server=server, count=count,
                              username=username, remote=remote)

    def mediaserver_image_cookies(self, server: Optional[str] = None,
                                  image_url: Optional[str] = None) -> Optional[Union[str, dict]]:
        """
        获取访问图片所需的 Cookies（仅部分后端实现，未实现者不参与分发）。

        :param server: 指定媒体服务器名称，None 表示全部
        :param image_url: 图片地址
        :return: 访问该图片所需的 Cookies
        """
        return self._dispatch("mediaserver_image_cookies", server=server, image_url=image_url)
