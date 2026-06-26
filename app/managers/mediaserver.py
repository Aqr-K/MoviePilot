from typing import Generator, List, Optional, Union, TYPE_CHECKING

from app.managers.base import ManagerBase
from app.schemas import (ExistMediaInfo, MediaServerItem, MediaServerLibrary,
                         MediaServerPlayItem, MediaServerSeasonInfo, Statistic)

if TYPE_CHECKING:
    from app.core.context import MediaInfo


class MediaServerManager(ManagerBase):
    """
    媒体服务器（MediaServer 域）统一入口（单例）。

    对外提供一组类型化的媒体服务器操作方法（契约见 app.modules.IMediaServer），按方法名分发到所有已启用的
    媒体服务器后端模块（内建 Emby/Jellyfin/Plex/TrimeMedia/Ugreen/ZSpace 及插件经 provides_mediaservers()
    注册的媒体服务器），并合并各后端结果。每次分发实时查询当前运行的后端，自动纳入运行期注册/卸载的插件。

    分发内核（单面 _dispatch / 合并 / 错误处理）见基类 ManagerBase——媒体服务器后端均经 provides_mediaservers()
    注册为运行模块，故只用系统后端面，无插件钩子面。

    约定：凡接受 server 形参的方法，传 None 时面向全部媒体服务器，传具体名称时只作用于该服务器。
    各后端 server 必填性 / username 形参存在差异，对外统一为最宽松签名并按关键字分发，对全部后端兼容。
    """

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
