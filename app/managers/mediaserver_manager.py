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
    媒体服务器（MediaServer 域）门面。

    对照下载器域的 DownloaderManager / 存储域的 FileManager：把"媒体服务器"领域升级为
    "门面 + 后端"模式——对外提供一组类型化、可发现的统一方法（实现 app.modules.IMediaServer
    契约的对外面），对内按方法名分发到所有 ModuleType.MediaServer 后端模块（内建 Emby/Jellyfin/
    Plex/TrimeMedia/Ugreen/ZSpace 以及插件经 provides_mediaservers() 注册的媒体服务器），并按与
    ChainBase.run_module 完全一致的合并语义（列表 extend / 非列表取首个非 None）汇总结果。

    设计要点：
    - **行为等价**：_dispatch 忠实复刻 ChainBase.__execute_system_modules 的分发与合并（含
      check_signature 分支、异常逐后端续跑、SystemError 事件与消息上报），调用的是与 run_module
      同一批后端模块方法（后端方法体零改动），故对真实媒体服务器的行为不变；唯一被收敛的是
      "字符串 ABI 分发"这一隐式面，被显式、类型化的门面取代。等价性测试见 tests/test_mediaserver_facade.py。
    - **签名漂移收敛**：各后端 mediaserver_* 的 server 必填性 / username 形参 / **kwargs 存在差异；
      门面统一为最宽松 canonical 签名并按 kwarg 分发——后端要么声明该形参、要么有 **kwargs 吸收，
      故与 run_module 一样对全部后端兼容（详见 app.modules.IMediaServer）。
    - **v2 兼容路径保留**：内建媒体服务器仍作为 _ModuleBase 模块注册，run_module("mediaserver_librarys")
      等字符串分发仍可用（标记为 v2 兼容路径、计划后续废弃）。门面不替换该路径，只作为新代码的
      首选入口叠加其上。
    - **后端发现**：每次分发实时查询 ModuleManager().get_running_modules(method)，自动纳入运行期
      注册/卸载的插件媒体服务器，无需门面侧维护后端清单。
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

    @staticmethod
    def _handle_rate_limit_error(err: RateLimitExceededException, module_id: str,
                                 method: str, raise_exception: bool) -> None:
        """
        本地限流跳过（复刻 ChainBase.__handle_rate_limit_error）：raise_exception 为真则抛出；
        否则仅 INFO 记录、不进系统错误告警（预期的限流状态不应触发 SystemError 事件/消息）。
        """
        if raise_exception:
            raise err
        logger.info(f"模块 {module_id}.{method} 已限流，跳过执行：{str(err)}")

    def _dispatch(self, method: str, *args, **kwargs) -> Any:
        """
        将媒体服务器方法按方法名分发到所有 MediaServer 后端模块并合并结果。

        合并语义与 ChainBase.__execute_system_modules 严格一致：按 get_priority() 升序遍历后端，
        - 结果为空（None/全 None 元组）→ 取该后端返回值；
        - 结果与方法签名一致（check_signature）→ 透传；
        - 结果为列表 → 合并后续后端的列表结果；
        - 否则（非空非列表，如 str/dict/生成器）→ 短路停止。
        单后端异常逐个捕获续跑，不影响其它后端；raise_exception=True 时透传首个异常。
        """
        # pop 而非 get：raise_exception 是分发器控制位，不应透传给不接受该参数的后端 func。
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
                # 限流先于通用异常处理（与 __execute_system_modules 一致）：安静跳过、不告警。
                self._handle_rate_limit_error(err, module_id, method, raise_exception)
            except Exception as err:
                self._handle_error(err, module_id, module_name, method, raise_exception)
        return result

    # ------------------------------------------------------------------ #
    # IMediaServer 对外面：签名与 ChainBase/MediaServerChain 媒服包装方法一致（收敛漂移后的 canonical 形）。
    # ------------------------------------------------------------------ #

    def media_exists(self, mediainfo: "MediaInfo", itemid: Optional[str] = None,
                     server: Optional[str] = None) -> Optional[ExistMediaInfo]:
        """
        判断媒体是否存在于媒体服务器。
        """
        return self._dispatch("media_exists", mediainfo=mediainfo, itemid=itemid, server=server)

    def media_statistic(self, server: Optional[str] = None) -> Optional[List[Statistic]]:
        """
        媒体数量统计。
        """
        return self._dispatch("media_statistic", server=server)

    def mediaserver_librarys(self, server: Optional[str] = None, username: Optional[str] = None,
                             hidden: Optional[bool] = False) -> Optional[List[MediaServerLibrary]]:
        """
        获取媒体服务器所有媒体库。
        """
        return self._dispatch("mediaserver_librarys", server=server, username=username, hidden=hidden)

    def mediaserver_items(self, server: Optional[str] = None, library_id: Union[str, int] = None,
                          start_index: Optional[int] = 0, limit: Optional[int] = -1) -> Optional[Generator]:
        """
        获取媒体服务器项目列表（生成器）。
        """
        return self._dispatch("mediaserver_items", server=server, library_id=library_id,
                              start_index=start_index, limit=limit)

    def mediaserver_iteminfo(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> Optional[MediaServerItem]:
        """
        获取媒体服务器项目信息。
        """
        return self._dispatch("mediaserver_iteminfo", server=server, item_id=item_id)

    def mediaserver_tv_episodes(self, server: Optional[str] = None,
                                item_id: Union[str, int] = None) -> Optional[List[MediaServerSeasonInfo]]:
        """
        获取媒体服务器剧集信息。
        """
        return self._dispatch("mediaserver_tv_episodes", server=server, item_id=item_id)

    def mediaserver_playing(self, server: Optional[str] = None, count: Optional[int] = 20,
                            username: Optional[str] = None) -> List[MediaServerPlayItem]:
        """
        获取媒体服务器正在播放信息。
        """
        return self._dispatch("mediaserver_playing", server=server, count=count, username=username)

    def mediaserver_play_url(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> Optional[str]:
        """
        获取播放地址。
        """
        return self._dispatch("mediaserver_play_url", server=server, item_id=item_id)

    def mediaserver_latest(self, server: Optional[str] = None, count: Optional[int] = 20,
                           username: Optional[str] = None) -> List[MediaServerPlayItem]:
        """
        获取媒体服务器最新入库条目。
        """
        return self._dispatch("mediaserver_latest", server=server, count=count, username=username)

    def mediaserver_latest_images(self, server: Optional[str] = None, count: Optional[int] = 10,
                                  username: Optional[str] = None,
                                  remote: Optional[bool] = False) -> List[str]:
        """
        获取最新入库条目海报作为壁纸。
        """
        return self._dispatch("mediaserver_latest_images", server=server, count=count,
                              username=username, remote=remote)

    def mediaserver_image_cookies(self, server: Optional[str] = None,
                                  image_url: Optional[str] = None) -> Optional[Union[str, dict]]:
        """
        获取图片的 Cookies（仅部分后端实现，未实现者不参与分发）。
        """
        return self._dispatch("mediaserver_image_cookies", server=server, image_url=image_url)
