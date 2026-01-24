import asyncio
import re
import time
from datetime import datetime, timedelta
from typing import Any, Optional, Dict, Union, List

from app.agent import agent_manager
from app.chain import ChainBase
from app.chain.download import DownloadChain
from app.chain.media import MediaChain
from app.chain.search import SearchChain
from app.chain.subscribe import SubscribeChain
from app.core.config import settings, global_vars
from app.core.context import MediaInfo, Context
from app.core.meta import MetaBase
from app.db.user_oper import UserOper
from app.helper.torrent import TorrentHelper
from app.log import logger
from app.schemas import Notification, NotExistMediaInfo, CommingMessage
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import EventType, MessageChannel, MediaType
from app.utils.string import StringUtils

# 当前页面
_current_page: int = 0
# 当前元数据
_current_meta: Optional[MetaBase] = None
# 当前媒体信息
_current_media: Optional[MediaInfo] = None


class MessageChain(ChainBase):
    """
    外来消息处理链
    """
    # 缓存的用户数据 {userid: {type: str, items: list}}
    _cache_file = "__user_messages__"
    # 每页数据量
    _page_size: int = 8
    # 用户会话信息 {userid: (session_id, last_time)}
    _user_sessions: Dict[Union[str, int], tuple] = {}
    # 会话超时时间（分钟）
    _session_timeout_minutes: int = 30

    @staticmethod
    def __get_noexits_info(
            _meta: MetaBase,
            _mediainfo: MediaInfo) -> Dict[Union[int, str], Dict[int, NotExistMediaInfo]]:
        """
        获取缺失的媒体信息
        """
        if _mediainfo.type == MediaType.TV:
            if not _mediainfo.seasons:
                # 补充媒体信息
                _mediainfo = MediaChain().recognize_media(mtype=_mediainfo.type,
                                                          tmdbid=_mediainfo.tmdb_id,
                                                          doubanid=_mediainfo.douban_id,
                                                          cache=False)
                if not _mediainfo:
                    logger.warn(f"{_mediainfo.tmdb_id or _mediainfo.douban_id} 媒体信息识别失败！")
                    return {}
                if not _mediainfo.seasons:
                    logger.warn(f"媒体信息中没有季集信息，"
                                f"标题：{_mediainfo.title}，"
                                f"tmdbid：{_mediainfo.tmdb_id}，doubanid：{_mediainfo.douban_id}")
                    return {}
            # KEY
            _mediakey = _mediainfo.tmdb_id or _mediainfo.douban_id
            _no_exists = {
                _mediakey: {}
            }
            if _meta.begin_season:
                # 指定季
                episodes = _mediainfo.seasons.get(_meta.begin_season)
                if not episodes:
                    return {}
                _no_exists[_mediakey][_meta.begin_season] = NotExistMediaInfo(
                    season=_meta.begin_season,
                    episodes=[],
                    total_episode=len(episodes),
                    start_episode=episodes[0]
                )
            else:
                # 所有季
                for sea, eps in _mediainfo.seasons.items():
                    if not eps:
                        continue
                    _no_exists[_mediakey][sea] = NotExistMediaInfo(
                        season=sea,
                        episodes=[],
                        total_episode=len(eps),
                        start_episode=eps[0]
                    )
        else:
            _no_exists = {}

        return _no_exists

    def process(self, body: Any, form: Any, args: Any) -> None:
        """
        调用模块识别消息内容
        """
        # 消息来源
        source = args.get("source")
        # 获取消息内容
        info = self.message_parser(source=source, body=body, form=form, args=args)
        if not info:
            return
        # 更新消息来源
        source = info.source
        # 渠道
        channel = info.channel
        # 用户ID
        userid = info.userid
        # 用户名
        username = info.username or userid
        if userid is None or userid == '':
            logger.debug(f'未识别到用户ID：{body}{form}{args}')
            return
        # 消息内容
        text = str(info.text).strip() if info.text else None
        if not text:
            logger.debug(f'未识别到消息内容：：{body}{form}{args}')
            return

        # 获取原消息ID信息
        original_message_id = info.message_id
        original_chat_id = info.chat_id

        # 处理消息
        self.handle_message(channel=channel, source=source, userid=userid, username=username, text=text,
                            original_message_id=original_message_id, original_chat_id=original_chat_id)

    def handle_message(self, channel: MessageChannel, source: str,
                       userid: Union[str, int], username: str, text: str,
                       original_message_id: Optional[Union[str, int]] = None,
                       original_chat_id: Optional[str] = None) -> None:
        """
        识别消息内容，执行操作
        """
        # 申明全局变量
        global _current_page, _current_meta, _current_media
        # 处理消息
        logger.info(f'收到用户消息内容，用户：{userid}，内容：{text}')
        # 加载缓存
        user_cache: Dict[str, dict] = self.load_cache(self._cache_file) or {}
        try:
            # 保存消息
            if not text.startswith('CALLBACK:'):
                self.messagehelper.put(
                    CommingMessage(
                        userid=userid,
                        username=username,
                        channel=channel,
                        source=source,
                        text=text
                    ), role="user")
                self.messageoper.add(
                    channel=channel,
                    source=source,
                    userid=username or userid,
                    text=text,
                    action=0
                )
            # 处理消息
            if text.startswith('CALLBACK:'):
                # 处理按钮回调（适配支持回调的渠），优先级最高
                if ChannelCapabilityManager.supports_callbacks(channel):
                    self._handle_callback(text=text, channel=channel, source=source,
                                          userid=userid, username=username,
                                          original_message_id=original_message_id, original_chat_id=original_chat_id)
                else:
                    logger.warning(f"渠道 {channel.value} 不支持回调，但收到了回调消息：{text}")
            elif text.startswith('/') and not text.lower().startswith('/ai'):
                # 执行特定命令命令（但不是/ai）
                self.eventmanager.send_event(
                    EventType.CommandExcute,
                    {
                        "cmd": text,
                        "user": userid,
                        "channel": channel,
                        "source": source
                    }
                )
            elif text.lower().startswith('/ai'):
                # 用户指定AI智能体消息响应
                self._handle_ai_message(text=text, channel=channel, source=source,
                                        userid=userid, username=username)
            elif settings.AI_AGENT_ENABLE and settings.AI_AGENT_GLOBAL:
                # 普通消息，全局智能体响应
                self._handle_ai_message(text=text, channel=channel, source=source,
                                        userid=userid, username=username)
            else:
                # 非智能体普通消息响应
                if text.isdigit():
                    # 用户选择了具体的条目
                    # 缓存
                    cache_data: dict = user_cache.get(userid)
                    if not cache_data:
                        # 发送消息
                        self.post_message(Notification(channel=channel, source=source, title="输入有误！", userid=userid))
                        return
                    cache_data = cache_data.copy()
                    # 选择项目
                    if not cache_data.get('items') \
                            or len(cache_data.get('items')) < int(text):
                        # 发送消息
                        self.post_message(Notification(channel=channel, source=source, title="输入有误！", userid=userid))
                        return
                    try:
                        # 选择的序号
                        _choice = int(text) + _current_page * self._page_size - 1
                        # 缓存类型
                        cache_type: str = cache_data.get('type')
                        # 缓存列表
                        cache_list: list = cache_data.get('items').copy()
                        # 选择
                        try:
                            if cache_type in ["Search", "ReSearch"]:
                                # 当前媒体信息
                                mediainfo: MediaInfo = cache_list[_choice]
                                _current_media = mediainfo
                                # 查询缺失的媒体信息
                                exist_flag, no_exists = DownloadChain().get_no_exists_info(meta=_current_meta,
                                                                                           mediainfo=_current_media)
                                if exist_flag and cache_type == "Search":
                                    # 媒体库中已存在
                                    self.post_message(
                                        Notification(channel=channel,
                                                     source=source,
                                                     title=f"【{_current_media.title_year}"
                                                           f"{_current_meta.sea} 媒体库中已存在，如需重新下载请发送：搜索 名称 或 下载 名称】",
                                                     userid=userid))
                                    return
                                elif exist_flag:
                                    # 没有缺失，但要全量重新搜索和下载
                                    no_exists = self.__get_noexits_info(_current_meta, _current_media)
                                # 发送缺失的媒体信息
                                messages = []
                                if no_exists and cache_type == "Search":
                                    # 发送缺失消息
                                    mediakey = mediainfo.tmdb_id or mediainfo.douban_id
                                    messages = [
                                        f"第 {sea} 季缺失 {StringUtils.str_series(no_exist.episodes) if no_exist.episodes else no_exist.total_episode} 集"
                                        for sea, no_exist in no_exists.get(mediakey).items()]
                                elif no_exists:
                                    # 发送总集数的消息
                                    mediakey = mediainfo.tmdb_id or mediainfo.douban_id
                                    messages = [
                                        f"第 {sea} 季总 {no_exist.total_episode} 集"
                                        for sea, no_exist in no_exists.get(mediakey).items()]
                                if messages:
                                    self.post_message(Notification(channel=channel,
                                                                   source=source,
                                                                   title=f"{mediainfo.title_year}：\n" + "\n".join(messages),
                                                                   userid=userid))
                                # 搜索种子，过滤掉不需要的剧集，以便选择
                                logger.info(f"开始搜索 {mediainfo.title_year} ...")
                                self.post_message(
                                    Notification(channel=channel,
                                                 source=source,
                                                 title=f"开始搜索 {mediainfo.type.value} {mediainfo.title_year} ...",
                                                 userid=userid))
                                # 开始搜索
                                contexts = SearchChain().process(mediainfo=mediainfo,
                                                                 no_exists=no_exists)
                                if not contexts:
                                    # 没有数据
                                    self.post_message(Notification(
                                        channel=channel,
                                        source=source,
                                        title=f"{mediainfo.title}"
                                              f"{_current_meta.sea} 未搜索到需要的资源！",
                                        userid=userid))
                                    return
                                # 搜索结果排序
                                contexts = TorrentHelper().sort_torrents(contexts)
                                try:
                                    # 判断是否设置自动下载
                                    auto_download_user = settings.AUTO_DOWNLOAD_USER
                                    # 匹配到自动下载用户
                                    if auto_download_user \
                                            and (auto_download_user == "all"
                                                 or any(userid == user for user in auto_download_user.split(","))):
                                        logger.info(f"用户 {userid} 在自动下载用户中，开始自动择优下载 ...")
                                        # 自动选择下载
                                        self.__auto_download(channel=channel,
                                                             source=source,
                                                             cache_list=contexts,
                                                             userid=userid,
                                                             username=username,
                                                             no_exists=no_exists)
                                    else:
                                        # 更新缓存
                                        user_cache[userid] = {
                                            "type": "Torrent",
                                            "items": contexts
                                        }
                                        _current_page = 0
                                        # 保存缓存
                                        self.save_cache(user_cache, self._cache_file)
                                        # 删除原消息
                                        if (original_message_id and original_chat_id and
                                                ChannelCapabilityManager.supports_deletion(channel)):
                                            self.delete_message(
                                                channel=channel,
                                                source=source,
                                                message_id=original_message_id,
                                                chat_id=original_chat_id
                                            )
                                        # 发送种子数据
                                        logger.info(f"搜索到 {len(contexts)} 条数据，开始发送选择消息 ...")
                                        self.__post_torrents_message(channel=channel,
                                                                     source=source,
                                                                     title=mediainfo.title,
                                                                     items=contexts[:self._page_size],
                                                                     userid=userid,
                                                                     total=len(contexts))
                                finally:
                                    contexts.clear()
                                    del contexts
                            elif cache_type in ["Subscribe", "ReSubscribe"]:
                                # 订阅或洗版媒体
                                mediainfo: MediaInfo = cache_list[_choice]
                                # 洗版标识
                                best_version = False
                                # 查询缺失的媒体信息
                                if cache_type == "Subscribe":
                                    exist_flag, _ = DownloadChain().get_no_exists_info(meta=_current_meta,
                                                                                       mediainfo=mediainfo)
                                    if exist_flag:
                                        self.post_message(Notification(
                                            channel=channel,
                                            source=source,
                                            title=f"【{mediainfo.title_year}"
                                                  f"{_current_meta.sea} 媒体库中已存在，如需洗版请发送：洗版 XXX】",
                                            userid=userid))
                                        return
                                else:
                                    best_version = True
                                # 转换用户名
                                mp_name = UserOper().get_name(
                                    **{f"{channel.name.lower()}_userid": userid}) if channel else None
                                # 添加订阅，状态为N
                                SubscribeChain().add(title=mediainfo.title,
                                                     year=mediainfo.year,
                                                     mtype=mediainfo.type,
                                                     tmdbid=mediainfo.tmdb_id,
                                                     season=_current_meta.begin_season,
                                                     channel=channel,
                                                     source=source,
                                                     userid=userid,
                                                     username=mp_name or username,
                                                     best_version=best_version)
                            elif cache_type == "Torrent":
                                if int(text) == 0:
                                    # 自动选择下载，强制下载模式
                                    self.__auto_download(channel=channel,
                                                         source=source,
                                                         cache_list=cache_list,
                                                         userid=userid,
                                                         username=username)
                                else:
                                    # 下载种子
                                    context: Context = cache_list[_choice]
                                    # 下载
                                    DownloadChain().download_single(context, channel=channel, source=source,
                                                                    userid=userid, username=username)
                        finally:
                            cache_list.clear()
                            del cache_list
                    finally:
                        cache_data.clear()
                        del cache_data
                elif text.lower() == "p":
                    # 上一页
                    cache_data: dict = user_cache.get(userid)
                    if not cache_data:
                        # 没有缓存
                        self.post_message(Notification(
                            channel=channel, source=source, title="输入有误！", userid=userid))
                        return
                    cache_data = cache_data.copy()
                    try:
                        if _current_page == 0:
                            # 第一页
                            self.post_message(Notification(
                                channel=channel, source=source, title="已经是第一页了！", userid=userid))
                            return
                        # 减一页
                        _current_page -= 1
                        cache_type: str = cache_data.get('type')
                        # 产生副本，避免修改原值
                        cache_list: list = cache_data.get('items').copy()
                        try:
                            if _current_page == 0:
                                start = 0
                                end = self._page_size
                            else:
                                start = _current_page * self._page_size
                                end = start + self._page_size
                            if cache_type == "Torrent":
                                # 发送种子数据
                                self.__post_torrents_message(channel=channel,
                                                             source=source,
                                                             title=_current_media.title,
                                                             items=cache_list[start:end],
                                                             userid=userid,
                                                             total=len(cache_list),
                                                             original_message_id=original_message_id,
                                                             original_chat_id=original_chat_id)
                            else:
                                # 发送媒体数据
                                self.__post_medias_message(channel=channel,
                                                           source=source,
                                                           title=_current_meta.name,
                                                           items=cache_list[start:end],
                                                           userid=userid,
                                                           total=len(cache_list),
                                                           original_message_id=original_message_id,
                                                           original_chat_id=original_chat_id)
                        finally:
                            cache_list.clear()
                            del cache_list
                    finally:
                        cache_data.clear()
                        del cache_data
                elif text.lower() == "n":
                    # 下一页
                    cache_data: dict = user_cache.get(userid)
                    if not cache_data:
                        # 没有缓存
                        self.post_message(Notification(
                            channel=channel, source=source, title="输入有误！", userid=userid))
                        return
                    cache_data = cache_data.copy()
                    try:
                        cache_type: str = cache_data.get('type')
                        # 产生副本，避免修改原值
                        cache_list: list = cache_data.get('items').copy()
                        total = len(cache_list)
                        # 加一页
                        cache_list = cache_list[(_current_page + 1) * self._page_size:(_current_page + 2) * self._page_size]
                        if not cache_list:
                            # 没有数据
                            self.post_message(Notification(
                                channel=channel, source=source, title="已经是最后一页了！", userid=userid))
                            return
                        else:
                            try:
                                # 加一页
                                _current_page += 1
                                if cache_type == "Torrent":
                                    # 发送种子数据
                                    self.__post_torrents_message(channel=channel,
                                                                 source=source,
                                                                 title=_current_media.title,
                                                                 items=cache_list,
                                                                 userid=userid,
                                                                 total=total,
                                                                 original_message_id=original_message_id,
                                                                 original_chat_id=original_chat_id)
                                else:
                                    # 发送媒体数据
                                    self.__post_medias_message(channel=channel,
                                                               source=source,
                                                               title=_current_meta.name,
                                                               items=cache_list,
                                                               userid=userid,
                                                               total=total,
                                                               original_message_id=original_message_id,
                                                               original_chat_id=original_chat_id)
                            finally:
                                cache_list.clear()
                                del cache_list
                    finally:
                        cache_data.clear()
                        del cache_data
                else:
                    # 搜索或订阅
                    if text.startswith("订阅"):
                        # 订阅
                        content = re.sub(r"订阅[:：\s]*", "", text)
                        action = "Subscribe"
                    elif text.startswith("洗版"):
                        # 洗版
                        content = re.sub(r"洗版[:：\s]*", "", text)
                        action = "ReSubscribe"
                    elif text.startswith("搜索") or text.startswith("下载"):
                        # 重新搜索/下载
                        content = re.sub(r"(搜索|下载)[:：\s]*", "", text)
                        action = "ReSearch"
                    elif text.startswith("#") \
                            or re.search(r"^请[问帮你]", text) \
                            or re.search(r"[?？]$", text) \
                            or StringUtils.count_words(text) > 10 \
                            or text.find("继续") != -1:
                        # 聊天
                        content = text
                        action = "Chat"
                    elif StringUtils.is_link(text):
                        # 链接
                        content = text
                        action = "Link"
                    else:
                        # 搜索
                        content = text
                        action = "Search"

                    if action in ["Search", "ReSearch", "Subscribe", "ReSubscribe"]:
                        # 搜索
                        meta, medias = MediaChain().search(content)
                        # 识别
                        if not meta.name:
                            self.post_message(Notification(
                                channel=channel, source=source, title="无法识别输入内容！", userid=userid))
                            return
                        # 开始搜索
                        if not medias:
                            self.post_message(Notification(
                                channel=channel, source=source, title=f"{meta.name} 没有找到对应的媒体信息！",
                                userid=userid))
                            return
                        logger.info(f"搜索到 {len(medias)} 条相关媒体信息")
                        try:
                            # 记录当前状态
                            _current_meta = meta
                            # 保存缓存
                            user_cache[userid] = {
                                'type': action,
                                'items': medias
                            }
                            self.save_cache(user_cache, self._cache_file)
                            _current_page = 0
                            _current_media = None
                            # 发送媒体列表
                            self.__post_medias_message(channel=channel,
                                                       source=source,
                                                       title=meta.name,
                                                       items=medias[:self._page_size],
                                                       userid=userid, total=len(medias))
                        finally:
                            medias.clear()
                            del medias
                    else:
                        # 广播事件
                        self.eventmanager.send_event(
                            EventType.UserMessage,
                            {
                                "text": content,
                                "userid": userid,
                                "channel": channel,
                                "source": source
                            }
                        )
        finally:
            user_cache.clear()
            del user_cache

    def _handle_callback(self, text: str, channel: MessageChannel, source: str,
                         userid: Union[str, int], username: str,
                         original_message_id: Optional[Union[str, int]] = None,
                         original_chat_id: Optional[str] = None) -> None:
        """
        处理按钮回调
        """

        global _current_media

        # 提取回调数据
        callback_data = text[9:]  # 去掉 "CALLBACK:" 前缀
        logger.info(f"处理按钮回调：{callback_data}")

        # 插件消息的事件回调 [PLUGIN]插件ID|内容
        if callback_data.startswith('[PLUGIN]'):
            # 提取插件ID和内容
            plugin_id, content = callback_data.split("|", 1)
            # 广播给插件处理
            self.eventmanager.send_event(
                EventType.MessageAction,
                {
                    "plugin_id": plugin_id.replace("[PLUGIN]", ""),
                    "text": content,
                    "userid": userid,
                    "channel": channel,
                    "source": source,
                    "original_message_id": original_message_id,
                    "original_chat_id": original_chat_id
                }
            )
            return

        # 解析系统回调数据
        try:
            page_text = callback_data.split("_", 1)[1]
            self.handle_message(channel=channel, source=source, userid=userid, username=username,
                                text=page_text,
                                original_message_id=original_message_id, original_chat_id=original_chat_id)
        except IndexError:
            logger.error(f"回调数据格式错误：{callback_data}")
            self.post_message(Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title="回调数据格式错误，请检查！"
            ))

    def __auto_download(self, channel: MessageChannel, source: str, cache_list: list[Context],
                        userid: Union[str, int], username: str,
                        no_exists: Optional[Dict[Union[int, str], Dict[int, NotExistMediaInfo]]] = None):
        """
        自动择优下载
        """
        downloadchain = DownloadChain()
        if no_exists is None:
            # 查询缺失的媒体信息
            exist_flag, no_exists = downloadchain.get_no_exists_info(
                meta=_current_meta,
                mediainfo=_current_media
            )
            if exist_flag:
                # 媒体库中已存在，查询全量
                no_exists = self.__get_noexits_info(_current_meta, _current_media)

        # 批量下载
        downloads, lefts = downloadchain.batch_download(contexts=cache_list,
                                                        no_exists=no_exists,
                                                        channel=channel,
                                                        source=source,
                                                        userid=userid,
                                                        username=username)
        if downloads and not lefts:
            # 全部下载完成
            logger.info(f'{_current_media.title_year} 下载完成')
        else:
            # 未完成下载
            logger.info(f'{_current_media.title_year} 未下载未完整，添加订阅 ...')
            if downloads and _current_media.type == MediaType.TV:
                # 获取已下载剧集
                downloaded = [download.meta_info.begin_episode for download in downloads
                              if download.meta_info.begin_episode]
                note = downloaded
            else:
                note = None
            # 转换用户名
            mp_name = UserOper().get_name(**{f"{channel.name.lower()}_userid": userid}) if channel else None
            # 添加订阅，状态为R
            SubscribeChain().add(title=_current_media.title,
                                 year=_current_media.year,
                                 mtype=_current_media.type,
                                 tmdbid=_current_media.tmdb_id,
                                 season=_current_meta.begin_season,
                                 channel=channel,
                                 source=source,
                                 userid=userid,
                                 username=mp_name or username,
                                 state="R",
                                 note=note)

    def __post_medias_message(self, channel: MessageChannel, source: str,
                              title: str, items: list, userid: str, total: int,
                              original_message_id: Optional[Union[str, int]] = None,
                              original_chat_id: Optional[str] = None):
        """
        发送媒体列表消息
        """
        # 检查渠道是否支持按钮
        supports_buttons = ChannelCapabilityManager.supports_buttons(channel)

        if supports_buttons:
            # 支持按钮的渠道
            if total > self._page_size:
                title = f"【{title}】共找到{total}条相关信息，请选择操作"
            else:
                title = f"【{title}】共找到{total}条相关信息，请选择操作"

            buttons = self._create_media_buttons(channel=channel, items=items, total=total)
        else:
            # 不支持按钮的渠道，使用文本提示
            if total > self._page_size:
                title = f"【{title}】共找到{total}条相关信息，请回复对应数字选择（p: 上一页 n: 下一页）"
            else:
                title = f"【{title}】共找到{total}条相关信息，请回复对应数字选择"
            buttons = None

        notification = Notification(
            channel=channel,
            source=source,
            title=title,
            userid=userid,
            buttons=buttons,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id
        )

        self.post_medias_message(notification, medias=items)

    def _create_media_buttons(self, channel: MessageChannel, items: list, total: int) -> List[List[Dict]]:
        """
        创建媒体选择按钮
        """
        global _current_page

        buttons = []
        max_text_length = ChannelCapabilityManager.get_max_button_text_length(channel)
        max_per_row = ChannelCapabilityManager.get_max_buttons_per_row(channel)

        # 为每个媒体项创建选择按钮
        current_row = []
        for i in range(len(items)):
            media = items[i]

            if max_per_row == 1:
                # 每行一个按钮，使用完整文本
                button_text = f"{i + 1}. {media.title_year}"
                if len(button_text) > max_text_length:
                    button_text = button_text[:max_text_length - 3] + "..."

                buttons.append([{
                    "text": button_text,
                    "callback_data": f"select_{i + 1}"
                }])
            else:
                # 多按钮一行的情况，使用简化文本
                button_text = f"{i + 1}"

                current_row.append({
                    "text": button_text,
                    "callback_data": f"select_{i + 1}"
                })

                # 如果当前行已满或者是最后一个按钮，添加到按钮列表
                if len(current_row) == max_per_row or i == len(items) - 1:
                    buttons.append(current_row)
                    current_row = []

        # 添加翻页按钮
        if total > self._page_size:
            page_buttons = []
            if _current_page > 0:
                page_buttons.append({"text": "⬅️ 上一页", "callback_data": "page_p"})
            if (_current_page + 1) * self._page_size < total:
                page_buttons.append({"text": "下一页 ➡️", "callback_data": "page_n"})
            if page_buttons:
                buttons.append(page_buttons)

        return buttons

    def __post_torrents_message(self, channel: MessageChannel, source: str,
                                title: str, items: list, userid: str, total: int,
                                original_message_id: Optional[Union[str, int]] = None,
                                original_chat_id: Optional[str] = None):
        """
        发送种子列表消息
        """
        # 检查渠道是否支持按钮
        supports_buttons = ChannelCapabilityManager.supports_buttons(channel)

        if supports_buttons:
            # 支持按钮的渠道
            if total > self._page_size:
                title = f"【{title}】共找到{total}条相关资源，请选择下载"
            else:
                title = f"【{title}】共找到{total}条相关资源，请选择下载"

            buttons = self._create_torrent_buttons(channel=channel, items=items, total=total)
        else:
            # 不支持按钮的渠道，使用文本提示
            if total > self._page_size:
                title = f"【{title}】共找到{total}条相关资源，请回复对应数字下载（0: 自动选择 p: 上一页 n: 下一页）"
            else:
                title = f"【{title}】共找到{total}条相关资源，请回复对应数字下载（0: 自动选择）"
            buttons = None

        notification = Notification(
            channel=channel,
            source=source,
            title=title,
            userid=userid,
            link=settings.MP_DOMAIN('#/resource'),
            buttons=buttons,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id
        )

        self.post_torrents_message(notification, torrents=items)

    def _create_torrent_buttons(self, channel: MessageChannel, items: list, total: int) -> List[List[Dict]]:
        """
        创建种子下载按钮
        """

        global _current_page

        buttons = []
        max_text_length = ChannelCapabilityManager.get_max_button_text_length(channel)
        max_per_row = ChannelCapabilityManager.get_max_buttons_per_row(channel)

        # 自动选择按钮
        buttons.append([{"text": "🤖 自动选择下载", "callback_data": "download_0"}])

        # 为每个种子项创建下载按钮
        current_row = []
        for i in range(len(items)):
            context = items[i]
            torrent = context.torrent_info

            if max_per_row == 1:
                # 每行一个按钮，使用完整文本
                button_text = f"{i + 1}. {torrent.site_name} - {torrent.seeders}↑"
                if len(button_text) > max_text_length:
                    button_text = button_text[:max_text_length - 3] + "..."

                buttons.append([{
                    "text": button_text,
                    "callback_data": f"download_{i + 1}"
                }])
            else:
                # 多按钮一行的情况，使用简化文本
                button_text = f"{i + 1}"

                current_row.append({
                    "text": button_text,
                    "callback_data": f"download_{i + 1}"
                })

                # 如果当前行已满或者是最后一个按钮，添加到按钮列表
                if len(current_row) == max_per_row or i == len(items) - 1:
                    buttons.append(current_row)
                    current_row = []

        # 添加翻页按钮
        if total > self._page_size:
            page_buttons = []
            if _current_page > 0:
                page_buttons.append({"text": "⬅️ 上一页", "callback_data": "page_p"})
            if (_current_page + 1) * self._page_size < total:
                page_buttons.append({"text": "下一页 ➡️", "callback_data": "page_n"})
            if page_buttons:
                buttons.append(page_buttons)

        return buttons

    def _get_or_create_session_id(self, userid: Union[str, int]) -> str:
        """
        获取或创建会话ID
        如果用户上次会话在15分钟内，则复用相同的会话ID；否则创建新的会话ID
        """
        current_time = datetime.now()

        # 检查用户是否有已存在的会话
        if userid in self._user_sessions:
            session_id, last_time = self._user_sessions[userid]

            # 计算时间差
            time_diff = current_time - last_time

            # 如果时间差小于等于xx分钟，复用会话ID
            if time_diff <= timedelta(minutes=self._session_timeout_minutes):
                # 更新最后使用时间
                self._user_sessions[userid] = (session_id, current_time)
                logger.info(
                    f"复用会话ID: {session_id}, 用户: {userid}, 距离上次会话: {time_diff.total_seconds() / 60:.1f}分钟")
                return session_id

        # 创建新的会话ID
        new_session_id = f"user_{userid}_{int(time.time())}"
        self._user_sessions[userid] = (new_session_id, current_time)
        logger.info(f"创建新会话ID: {new_session_id}, 用户: {userid}")
        return new_session_id

    def clear_user_session(self, userid: Union[str, int]) -> bool:
        """
        清除指定用户的会话信息
        返回是否成功清除
        """
        if userid in self._user_sessions:
            session_id, _ = self._user_sessions.pop(userid)
            logger.info(f"已清除用户 {userid} 的会话: {session_id}")
            return True
        return False

    def remote_clear_session(self, channel: MessageChannel, userid: Union[str, int], source: Optional[str] = None):
        """
        清除用户会话（远程命令接口）
        """
        # 获取并清除会话信息
        session_id = None
        if userid in self._user_sessions:
            session_id, _ = self._user_sessions.pop(userid)
            logger.info(f"已清除用户 {userid} 的会话: {session_id}")

        # 如果有会话ID，同时清除智能体的会话记忆
        if session_id:
            try:
                asyncio.run_coroutine_threadsafe(
                    agent_manager.clear_session(
                        session_id=session_id,
                        user_id=str(userid)
                    ),
                    global_vars.loop
                )
            except Exception as e:
                logger.warning(f"清除智能体会话记忆失败: {e}")

            self.post_message(Notification(
                channel=channel,
                source=source,
                title="智能体会话已清除，下次将创建新的会话",
                userid=userid
            ))
        else:
            self.post_message(Notification(
                channel=channel,
                source=source,
                title="您当前没有活跃的智能体会话",
                userid=userid
            ))

    def _handle_ai_message(self, text: str, channel: MessageChannel, source: str,
                           userid: Union[str, int], username: str) -> None:
        """
        处理AI智能体消息
        """
        try:
            # 检查AI智能体是否启用
            if not settings.AI_AGENT_ENABLE:
                self.post_message(Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="MoviePilot智能助手未启用，请在系统设置中启用"
                ))
                return

            # 提取用户消息
            if text.lower().startswith("/ai"):
                user_message = text[3:].strip()  # 移除 "/ai" 前缀（大小写不敏感）
            else:
                user_message = text.strip()  # 按原消息处理
            if not user_message:
                self.post_message(Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="请输入您的问题或需求"
                ))
                return

            # 生成或复用会话ID
            session_id = self._get_or_create_session_id(userid)

            # 在事件循环中处理
            asyncio.run_coroutine_threadsafe(
                agent_manager.process_message(
                    session_id=session_id,
                    user_id=str(userid),
                    message=user_message,
                    channel=channel.value if channel else None,
                    source=source,
                    username=username
                ),
                global_vars.loop
            )

        except Exception as e:
            logger.error(f"处理AI智能体消息失败: {e}")
            self.messagehelper.put(f"AI智能体处理失败: {str(e)}", role="system", title="MoviePilot助手")
