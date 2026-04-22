import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple, Union

from app.chain import ChainBase
from app.chain.download import DownloadChain
from app.chain.media import MediaChain
from app.chain.search import SearchChain
from app.chain.subscribe import SubscribeChain
from app.core.config import settings
from app.core.context import Context, MediaInfo
from app.core.meta import MetaBase
from app.db.user_oper import UserOper
from app.helper.torrent import TorrentHelper
from app.log import logger
from app.schemas import Notification, NotExistMediaInfo
from app.schemas.message import ChannelCapabilityManager
from app.schemas.types import MediaType, MessageChannel
from app.utils.string import StringUtils


@dataclass(frozen=True)
class AgentInteractionOption:
    """
    Agent 交互选项。
    """

    label: str
    value: str


@dataclass
class PendingAgentInteraction:
    """
    待处理的 Agent 客户端交互请求。
    """

    request_id: str
    session_id: str
    user_id: str
    channel: Optional[str]
    source: Optional[str]
    username: Optional[str]
    title: Optional[str]
    prompt: str
    options: List[AgentInteractionOption]
    created_at: datetime = field(default_factory=datetime.now)


class AgentInteractionManager:
    """
    管理 Agent 发起的客户端交互请求。
    """

    _ttl = timedelta(hours=24)

    def __init__(self):
        self._pending_interactions: Dict[str, PendingAgentInteraction] = {}
        self._lock = Lock()

    def _cleanup_locked(self) -> None:
        expire_before = datetime.now() - self._ttl
        expired_ids = [
            request_id
            for request_id, request in self._pending_interactions.items()
            if request.created_at < expire_before
        ]
        for request_id in expired_ids:
            self._pending_interactions.pop(request_id, None)

    def create_request(
        self,
        session_id: str,
        user_id: str,
        channel: Optional[str],
        source: Optional[str],
        username: Optional[str],
        title: Optional[str],
        prompt: str,
        options: List[AgentInteractionOption],
    ) -> PendingAgentInteraction:
        """
        创建一条待用户确认的 Agent 交互请求。
        """
        with self._lock:
            self._cleanup_locked()
            request_id = uuid.uuid4().hex[:12]
            while request_id in self._pending_interactions:
                request_id = uuid.uuid4().hex[:12]
            request = PendingAgentInteraction(
                request_id=request_id,
                session_id=session_id,
                user_id=str(user_id),
                channel=channel,
                source=source,
                username=username,
                title=title,
                prompt=prompt,
                options=options,
            )
            self._pending_interactions[request_id] = request
            return request

    def resolve(
        self,
        request_id: str,
        option_index: int,
        user_id: Optional[str] = None,
    ) -> Optional[tuple[PendingAgentInteraction, AgentInteractionOption]]:
        """
        消费一条 Agent 交互请求，并返回选中的选项。
        """
        with self._lock:
            self._cleanup_locked()
            request = self._pending_interactions.get(request_id)
            if not request:
                return None
            if user_id is not None and str(request.user_id) != str(user_id):
                return None
            if option_index < 1 or option_index > len(request.options):
                return None
            option = request.options[option_index - 1]
            self._pending_interactions.pop(request_id, None)
            return request, option

    def clear(self) -> None:
        """
        清空所有 Agent 交互请求。
        """
        with self._lock:
            self._pending_interactions.clear()


agent_interaction_manager = AgentInteractionManager()


@dataclass
class PendingMediaInteraction:
    """
    记录一次搜索/下载/订阅交互的当前上下文。
    """

    request_id: str
    user_id: str
    channel: Optional[MessageChannel]
    source: Optional[str]
    username: Optional[str]
    action: str
    keyword: str
    phase: str = "media"
    page: int = 0
    title: str = ""
    meta: Optional[MetaBase] = None
    current_media: Optional[MediaInfo] = None
    items: List[Any] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


class MediaInteractionManager:
    """
    管理用户当前激活的媒体交互状态。

    每个用户只保留一个有效会话，避免旧按钮与新一轮搜索混用。
    """

    _ttl = timedelta(hours=24)

    def __init__(self):
        self._by_id: Dict[str, PendingMediaInteraction] = {}
        self._by_user: Dict[str, str] = {}
        self._lock = Lock()

    def _cleanup_locked(self) -> None:
        """
        清理超时会话，避免内存中残留旧交互状态。
        """
        expire_before = datetime.now() - self._ttl
        expired = [
            request_id
            for request_id, request in self._by_id.items()
            if request.created_at < expire_before
        ]
        for request_id in expired:
            request = self._by_id.pop(request_id, None)
            if request:
                self._by_user.pop(str(request.user_id), None)

    def create_or_replace(
        self,
        user_id: Union[str, int],
        channel: Optional[MessageChannel],
        source: Optional[str],
        username: Optional[str],
        action: str,
        keyword: str,
        title: str = "",
        meta: Optional[MetaBase] = None,
        items: Optional[List[Any]] = None,
    ) -> PendingMediaInteraction:
        """
        为用户创建新的交互状态，并替换旧会话。
        """
        with self._lock:
            self._cleanup_locked()
            user_key = str(user_id)
            old_request_id = self._by_user.get(user_key)
            if old_request_id:
                self._by_id.pop(old_request_id, None)

            request = PendingMediaInteraction(
                request_id=uuid.uuid4().hex[:12],
                user_id=user_key,
                channel=channel,
                source=source,
                username=username,
                action=action,
                keyword=keyword,
                title=title,
                meta=meta,
                items=list(items or []),
            )
            self._by_id[request.request_id] = request
            self._by_user[user_key] = request.request_id
            return request

    def get_by_user(
        self, user_id: Union[str, int]
    ) -> Optional[PendingMediaInteraction]:
        """
        按用户读取当前会话，供文本回复和旧按钮兼容使用。
        """
        with self._lock:
            self._cleanup_locked()
            request_id = self._by_user.get(str(user_id))
            if not request_id:
                return None
            return self._by_id.get(request_id)

    def get_by_id(
        self, request_id: str, user_id: Union[str, int]
    ) -> Optional[PendingMediaInteraction]:
        """
        按请求 ID 读取会话，并校验用户归属。
        """
        with self._lock:
            self._cleanup_locked()
            request = self._by_id.get(request_id)
            if not request or str(request.user_id) != str(user_id):
                return None
            return request

    def remove(self, request_id: str) -> None:
        """
        主动结束一条会话。
        """
        with self._lock:
            request = self._by_id.pop(request_id, None)
            if request:
                self._by_user.pop(str(request.user_id), None)

    def clear(self) -> None:
        """
        清空所有交互状态，主要用于测试。
        """
        with self._lock:
            self._by_id.clear()
            self._by_user.clear()


media_interaction_manager = MediaInteractionManager()


class MediaInteractionChain(ChainBase):
    """
    处理媒体搜索、订阅、资源选择和翻页等交互流程。
    """

    _button_page_size = 8
    _text_page_size = 8

    @staticmethod
    def has_pending_interaction(user_id: Union[str, int]) -> bool:
        """
        判断用户当前是否存在未结束的媒体交互。
        """
        return media_interaction_manager.get_by_user(user_id) is not None

    @staticmethod
    def _get_noexits_info(
        meta: MetaBase, mediainfo: MediaInfo
    ) -> Dict[Union[int, str], Dict[int, NotExistMediaInfo]]:
        """
        构造媒体缺失集信息，用于全量重搜或自动下载补全集数。
        """
        if mediainfo.type == MediaType.TV:
            if not mediainfo.seasons:
                mediainfo = MediaChain().recognize_media(
                    mtype=mediainfo.type,
                    tmdbid=mediainfo.tmdb_id,
                    doubanid=mediainfo.douban_id,
                    cache=False,
                )
                if not mediainfo:
                    logger.warn("媒体信息识别失败，无法补充季集信息")
                    return {}
                if not mediainfo.seasons:
                    logger.warn(
                        "媒体信息中没有季集信息，标题：%s，tmdbid：%s，doubanid：%s",
                        mediainfo.title,
                        mediainfo.tmdb_id,
                        mediainfo.douban_id,
                    )
                    return {}

            mediakey = mediainfo.tmdb_id or mediainfo.douban_id
            no_exists = {mediakey: {}}
            if meta.begin_season:
                episodes = mediainfo.seasons.get(meta.begin_season)
                if not episodes:
                    return {}
                no_exists[mediakey][meta.begin_season] = NotExistMediaInfo(
                    season=meta.begin_season,
                    episodes=[],
                    total_episode=len(episodes),
                    start_episode=episodes[0],
                )
            else:
                for sea, eps in mediainfo.seasons.items():
                    if not eps:
                        continue
                    no_exists[mediakey][sea] = NotExistMediaInfo(
                        season=sea,
                        episodes=[],
                        total_episode=len(eps),
                        start_episode=eps[0],
                    )
            return no_exists
        return {}

    @staticmethod
    def parse_callback(
        callback_data: str,
    ) -> Optional[Tuple[Optional[str], str, Optional[int]]]:
        """
        解析新旧两种媒体交互按钮格式。
        """
        if callback_data.startswith("media:"):
            parts = callback_data.split(":")
            if len(parts) < 3:
                return None
            request_id = parts[1]
            action = parts[2]
            index = None
            if len(parts) >= 4 and parts[3].isdigit():
                index = int(parts[3])
            return request_id, action, index

        match = re.match(r"^(select|download)_(\d+)$", callback_data)
        if match:
            return None, match.group(1), int(match.group(2))
        if callback_data == "page_p":
            return None, "page-prev", None
        if callback_data == "page_n":
            return None, "page-next", None
        return None

    def handle_callback_interaction(
        self,
        callback_data: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> bool:
        """
        处理按钮回调，并将当前视图刷新到原消息上。
        """
        parsed = self.parse_callback(callback_data)
        if not parsed:
            return False

        request_id, action, index = parsed
        if request_id:
            request = media_interaction_manager.get_by_id(request_id, userid)
        else:
            request = media_interaction_manager.get_by_user(userid)

        if not request:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="交互已失效，请重新搜索或订阅",
                )
            )
            return True

        request.channel = channel
        request.source = source
        request.username = username

        if action == "page-prev":
            if request.page <= 0:
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="已经是第一页了！",
                )
                return True
            request.page -= 1
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
            return True

        if action == "page-next":
            if not self._has_next_page(request):
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="已经是最后一页了！",
                )
                return True
            request.page += 1
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
            return True

        if action == "select":
            self._handle_media_selection(
                request=request,
                page_index=index,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
            return True

        if action == "download":
            self._handle_torrent_selection(
                request=request,
                page_index=index,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return True

        return False

    def handle_text_interaction(
        self,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        text: str,
    ) -> bool:
        """
        处理文本式交互。

        有会话时优先处理数字选择和翻页；无会话时负责识别搜索/订阅类入口。
        """
        request = media_interaction_manager.get_by_user(userid)
        normalized = (text or "").strip()
        lowered = normalized.lower()

        if request and lowered in {"退出", "关闭", "q", "quit", "exit"}:
            media_interaction_manager.remove(request.request_id)
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="媒体交互已结束",
                )
            )
            return True

        if normalized.isdigit():
            if not request:
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                )
                return True
            request.channel = channel
            request.source = source
            request.username = username
            index = int(normalized)
            if request.phase == "torrent":
                self._handle_torrent_selection(
                    request=request,
                    page_index=index,
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                )
            else:
                self._handle_media_selection(
                    request=request,
                    page_index=index,
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                )
            return True

        if lowered in {"p", "prev", "上一页"}:
            if not request:
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                )
                return True
            if request.page <= 0:
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="已经是第一页了！",
                )
                return True
            request.page -= 1
            request.channel = channel
            request.source = source
            request.username = username
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
            )
            return True

        if lowered in {"n", "next", "下一页"}:
            if not request:
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                )
                return True
            if not self._has_next_page(request):
                self._post_invalid_input(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title="已经是最后一页了！",
                )
                return True
            request.page += 1
            request.channel = channel
            request.source = source
            request.username = username
            self._render_interaction(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
            )
            return True

        action, content = self._resolve_action(normalized)
        if not action:
            return False

        self._start_media_interaction(
            action=action,
            content=content,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
        )
        return True

    @staticmethod
    def _resolve_action(text: str) -> Tuple[Optional[str], str]:
        """
        将用户输入归类为搜索、订阅或普通聊天。
        """
        if text.startswith("订阅"):
            return "Subscribe", re.sub(r"订阅[:：\s]*", "", text)
        if text.startswith("洗版"):
            return "ReSubscribe", re.sub(r"洗版[:：\s]*", "", text)
        if text.startswith("搜索") or text.startswith("下载"):
            return "ReSearch", re.sub(r"(搜索|下载)[:：\s]*", "", text)
        if StringUtils.is_link(text):
            return None, text
        if not StringUtils.is_media_title_like(text):
            return None, text
        return "Search", text

    def _start_media_interaction(
        self,
        action: str,
        content: str,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> None:
        """
        根据用户输入搜索媒体，并进入媒体选择阶段。
        """
        meta, medias = MediaChain().search(content)
        if not meta.name:
            self._post_invalid_input(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title="无法识别输入内容！",
            )
            return
        if not medias:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=f"{meta.name} 没有找到对应的媒体信息！",
                )
            )
            return

        logger.info("搜索到 %s 条相关媒体信息", len(medias))
        request = media_interaction_manager.create_or_replace(
            user_id=userid,
            channel=channel,
            source=source,
            username=username,
            action=action,
            keyword=content,
            title=meta.name,
            meta=meta,
            items=medias,
        )
        self._render_interaction(
            request=request,
            channel=channel,
            source=source,
            userid=userid,
        )

    def _handle_media_selection(
        self,
        request: PendingMediaInteraction,
        page_index: Optional[int],
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        处理媒体选择阶段的序号输入。
        """
        page_items, page, _ = self._page_items(
            items=request.items,
            page=request.page,
            page_size=self._page_size(request.channel),
        )
        request.page = page
        if not page_index or page_index < 1 or page_index > len(page_items):
            self._post_invalid_input(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return

        mediainfo: MediaInfo = page_items[page_index - 1]
        request.current_media = mediainfo

        if request.action in {"Search", "ReSearch"}:
            self._search_media_resources(
                request=request,
                mediainfo=mediainfo,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
            return

        if request.action in {"Subscribe", "ReSubscribe"}:
            self._subscribe_media(
                request=request,
                mediainfo=mediainfo,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )

    def _search_media_resources(
        self,
        request: PendingMediaInteraction,
        mediainfo: MediaInfo,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        根据已选媒体搜索资源，并切换到资源选择阶段。
        """
        exist_flag, no_exists = DownloadChain().get_no_exists_info(
            meta=request.meta,
            mediainfo=mediainfo,
        )
        if exist_flag and request.action == "Search":
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=f"【{mediainfo.title_year}{request.meta.sea} 媒体库中已存在，如需重新下载请发送：搜索 名称 或 下载 名称】",
                )
            )
            return
        if exist_flag:
            no_exists = self._get_noexits_info(request.meta, mediainfo)

        messages = self._build_no_exists_messages(
            mediainfo=mediainfo,
            no_exists=no_exists,
            show_missing_only=request.action == "Search",
        )
        if messages:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=f"{mediainfo.title_year}：\n" + "\n".join(messages),
                )
            )

        logger.info("开始搜索 %s ...", mediainfo.title_year)
        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=f"开始搜索 {mediainfo.type.value} {mediainfo.title_year} ...",
            )
        )

        contexts = SearchChain().process(mediainfo=mediainfo, no_exists=no_exists)
        if not contexts:
            self.post_message(
                Notification(
                    channel=channel,
                    source=source,
                    userid=userid,
                    username=username,
                    title=f"{mediainfo.title}{request.meta.sea} 未搜索到需要的资源！",
                )
            )
            return

        contexts = TorrentHelper().sort_torrents(contexts)
        if self._should_auto_download(userid):
            logger.info("用户 %s 在自动下载用户中，开始自动择优下载 ...", userid)
            self._auto_download(
                request=request,
                cache_list=contexts,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                no_exists=no_exists,
            )
            return

        request.phase = "torrent"
        request.page = 0
        request.title = mediainfo.title
        request.items = list(contexts)
        self._render_interaction(
            request=request,
            channel=channel,
            source=source,
            userid=userid,
            original_message_id=original_message_id,
            original_chat_id=original_chat_id,
        )

    def _subscribe_media(
        self,
        request: PendingMediaInteraction,
        mediainfo: MediaInfo,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> None:
        """
        根据已选媒体创建订阅或洗版订阅。
        """
        best_version = request.action == "ReSubscribe"
        if not best_version:
            exist_flag, _ = DownloadChain().get_no_exists_info(
                meta=request.meta,
                mediainfo=mediainfo,
            )
            if exist_flag:
                self.post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        userid=userid,
                        username=username,
                        title=f"【{mediainfo.title_year}{request.meta.sea} 媒体库中已存在，如需洗版请发送：洗版 XXX】",
                    )
                )
                return

        mp_name = (
            UserOper().get_name(**{f"{channel.name.lower()}_userid": userid})
            if channel
            else None
        )
        SubscribeChain().add(
            title=mediainfo.title,
            year=mediainfo.year,
            mtype=mediainfo.type,
            tmdbid=mediainfo.tmdb_id,
            season=request.meta.begin_season,
            channel=channel,
            source=source,
            userid=userid,
            username=mp_name or username,
            best_version=best_version,
        )

    def _handle_torrent_selection(
        self,
        request: PendingMediaInteraction,
        page_index: Optional[int],
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
    ) -> None:
        """
        处理资源选择阶段的下载操作。
        """
        if request.phase != "torrent":
            self._post_invalid_input(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return

        if page_index == 0:
            self._auto_download(
                request=request,
                cache_list=request.items,
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return

        page_items, page, _ = self._page_items(
            items=request.items,
            page=request.page,
            page_size=self._page_size(request.channel),
        )
        request.page = page
        if not page_index or page_index < 1 or page_index > len(page_items):
            self._post_invalid_input(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
            )
            return

        context: Context = page_items[page_index - 1]
        DownloadChain().download_single(
            context,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
        )

    def _auto_download(
        self,
        request: PendingMediaInteraction,
        cache_list: List[Context],
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: str,
        no_exists: Optional[Dict[Union[int, str], Dict[int, NotExistMediaInfo]]] = None,
    ) -> None:
        """
        自动择优下载当前资源列表，并在未完成时补建订阅。
        """
        downloadchain = DownloadChain()
        if no_exists is None:
            exist_flag, no_exists = downloadchain.get_no_exists_info(
                meta=request.meta,
                mediainfo=request.current_media,
            )
            if exist_flag:
                no_exists = self._get_noexits_info(request.meta, request.current_media)

        downloads, lefts = downloadchain.batch_download(
            contexts=cache_list,
            no_exists=no_exists,
            channel=channel,
            source=source,
            userid=userid,
            username=username,
        )
        if downloads and not lefts:
            logger.info("%s 下载完成", request.current_media.title_year)
            return

        logger.info("%s 未下载未完整，添加订阅 ...", request.current_media.title_year)
        if downloads and request.current_media.type == MediaType.TV:
            note = [
                download.meta_info.begin_episode
                for download in downloads
                if download.meta_info.begin_episode
            ]
        else:
            note = None

        mp_name = (
            UserOper().get_name(**{f"{channel.name.lower()}_userid": userid})
            if channel
            else None
        )
        SubscribeChain().add(
            title=request.current_media.title,
            year=request.current_media.year,
            mtype=request.current_media.type,
            tmdbid=request.current_media.tmdb_id,
            season=request.meta.begin_season,
            channel=channel,
            source=source,
            userid=userid,
            username=mp_name or username,
            state="R",
            note=note,
        )

    def _render_interaction(
        self,
        request: PendingMediaInteraction,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        按当前阶段渲染媒体列表或资源列表。
        """
        if request.phase == "torrent":
            self._post_torrents_message(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )
        else:
            self._post_medias_message(
                request=request,
                channel=channel,
                source=source,
                userid=userid,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            )

    def _post_medias_message(
        self,
        request: PendingMediaInteraction,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        发送或更新媒体选择列表。
        """
        page_items, page, total_pages = self._page_items(
            items=request.items,
            page=request.page,
            page_size=self._page_size(channel),
        )
        request.page = page
        total = len(request.items)
        if self._supports_interactive_buttons(channel):
            title = f"【{request.title}】共找到{total}条相关信息，请选择操作"
            buttons = self._create_media_buttons(
                channel=channel,
                request=request,
                items=page_items,
                total=total,
                total_pages=total_pages,
            )
        else:
            if total > self._page_size(channel):
                title = f"【{request.title}】共找到{total}条相关信息，请回复对应数字选择（p: 上一页 n: 下一页）"
            else:
                title = f"【{request.title}】共找到{total}条相关信息，请回复对应数字选择"
            buttons = None

        self.post_medias_message(
            Notification(
                channel=channel,
                source=source,
                title=title,
                userid=userid,
                buttons=buttons,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            ),
            medias=page_items,
        )

    def _post_torrents_message(
        self,
        request: PendingMediaInteraction,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        original_message_id: Optional[Union[str, int]] = None,
        original_chat_id: Optional[str] = None,
    ) -> None:
        """
        发送或更新资源选择列表。
        """
        page_items, page, total_pages = self._page_items(
            items=request.items,
            page=request.page,
            page_size=self._page_size(channel),
        )
        request.page = page
        total = len(request.items)
        if self._supports_interactive_buttons(channel):
            title = f"【{request.title}】共找到{total}条相关资源，请选择下载"
            buttons = self._create_torrent_buttons(
                channel=channel,
                request=request,
                items=page_items,
                total=total,
                total_pages=total_pages,
            )
        else:
            if total > self._page_size(channel):
                title = f"【{request.title}】共找到{total}条相关资源，请回复对应数字下载（0: 自动选择 p: 上一页 n: 下一页）"
            else:
                title = f"【{request.title}】共找到{total}条相关资源，请回复对应数字下载（0: 自动选择）"
            buttons = None

        self.post_torrents_message(
            Notification(
                channel=channel,
                source=source,
                title=title,
                userid=userid,
                link=settings.MP_DOMAIN("#/resource"),
                buttons=buttons,
                original_message_id=original_message_id,
                original_chat_id=original_chat_id,
            ),
            torrents=page_items,
        )

    def _create_media_buttons(
        self,
        channel: MessageChannel,
        request: PendingMediaInteraction,
        items: List[MediaInfo],
        total: int,
        total_pages: int,
    ) -> List[List[Dict[str, str]]]:
        """
        为媒体列表生成选择和翻页按钮。
        """
        buttons: List[List[Dict[str, str]]] = []
        max_text_length = ChannelCapabilityManager.get_max_button_text_length(channel)
        max_per_row = ChannelCapabilityManager.get_max_buttons_per_row(channel)

        current_row: List[Dict[str, str]] = []
        for index, media in enumerate(items, start=1):
            if max_per_row == 1:
                button_text = f"{index}. {media.title_year}"
                if len(button_text) > max_text_length:
                    button_text = button_text[: max_text_length - 3] + "..."
                buttons.append(
                    [
                        {
                            "text": button_text,
                            "callback_data": f"media:{request.request_id}:select:{index}",
                        }
                    ]
                )
                continue

            current_row.append(
                {
                    "text": f"{index}",
                    "callback_data": f"media:{request.request_id}:select:{index}",
                }
            )
            if len(current_row) == max_per_row or index == len(items):
                buttons.append(current_row)
                current_row = []

        if total > self._page_size(channel):
            buttons.extend(self._navigation_buttons(request, total_pages))
        return buttons

    def _create_torrent_buttons(
        self,
        channel: MessageChannel,
        request: PendingMediaInteraction,
        items: List[Context],
        total: int,
        total_pages: int,
    ) -> List[List[Dict[str, str]]]:
        """
        为资源列表生成下载和翻页按钮。
        """
        buttons: List[List[Dict[str, str]]] = [
            [
                {
                    "text": "🤖 自动选择下载",
                    "callback_data": f"media:{request.request_id}:download:0",
                }
            ]
        ]
        max_text_length = ChannelCapabilityManager.get_max_button_text_length(channel)
        max_per_row = ChannelCapabilityManager.get_max_buttons_per_row(channel)

        current_row: List[Dict[str, str]] = []
        for index, context in enumerate(items, start=1):
            torrent = context.torrent_info
            if max_per_row == 1:
                button_text = f"{index}. {torrent.site_name} - {torrent.seeders}↑"
                if len(button_text) > max_text_length:
                    button_text = button_text[: max_text_length - 3] + "..."
                buttons.append(
                    [
                        {
                            "text": button_text,
                            "callback_data": f"media:{request.request_id}:download:{index}",
                        }
                    ]
                )
                continue

            current_row.append(
                {
                    "text": f"{index}",
                    "callback_data": f"media:{request.request_id}:download:{index}",
                }
            )
            if len(current_row) == max_per_row or index == len(items):
                buttons.append(current_row)
                current_row = []

        if total > self._page_size(channel):
            buttons.extend(self._navigation_buttons(request, total_pages))
        return buttons

    def _has_next_page(self, request: PendingMediaInteraction) -> bool:
        """
        判断当前视图是否还有下一页。
        """
        _, page, total_pages = self._page_items(
            items=request.items,
            page=request.page,
            page_size=self._page_size(request.channel),
        )
        return page < total_pages - 1

    @staticmethod
    def _navigation_buttons(
        request: PendingMediaInteraction,
        total_pages: int,
    ) -> List[List[Dict[str, str]]]:
        """
        按当前页状态生成上一页和下一页按钮。
        """
        buttons: List[List[Dict[str, str]]] = []
        nav_row: List[Dict[str, str]] = []
        if request.page > 0:
            nav_row.append(
                {
                    "text": "⬅️ 上一页",
                    "callback_data": f"media:{request.request_id}:page-prev",
                }
            )
        if request.page < total_pages - 1:
            nav_row.append(
                {
                    "text": "下一页 ➡️",
                    "callback_data": f"media:{request.request_id}:page-next",
                }
            )
        if nav_row:
            buttons.append(nav_row)
        return buttons

    @staticmethod
    def _page_items(
        items: List[Any],
        page: int,
        page_size: int,
    ) -> Tuple[List[Any], int, int]:
        """
        返回当前页数据，并把页码限制在有效范围内。
        """
        total_pages = max(1, math.ceil(len(items) / page_size)) if page_size else 1
        page = min(max(0, page), total_pages - 1)
        start = page * page_size
        end = start + page_size
        return items[start:end], page, total_pages

    def _page_size(self, channel: Optional[MessageChannel]) -> int:
        """
        按渠道交互能力选择分页大小。
        """
        return (
            self._button_page_size
            if self._supports_interactive_buttons(channel)
            else self._text_page_size
        )

    @staticmethod
    def _supports_interactive_buttons(channel: Optional[MessageChannel]) -> bool:
        """
        判断渠道是否同时支持按钮展示与按钮回调。
        """
        return bool(
            channel
            and ChannelCapabilityManager.supports_buttons(channel)
            and ChannelCapabilityManager.supports_callbacks(channel)
        )

    @staticmethod
    def _build_no_exists_messages(
        mediainfo: MediaInfo,
        no_exists: Optional[Dict[Union[int, str], Dict[int, NotExistMediaInfo]]],
        show_missing_only: bool,
    ) -> List[str]:
        """
        将缺失集信息转换为可发送的文案。
        """
        if not no_exists:
            return []
        mediakey = mediainfo.tmdb_id or mediainfo.douban_id
        season_map = no_exists.get(mediakey) or {}
        if show_missing_only:
            return [
                f"第 {sea} 季缺失 {StringUtils.str_series(no_exist.episodes) if no_exist.episodes else no_exist.total_episode} 集"
                for sea, no_exist in season_map.items()
            ]
        return [
            f"第 {sea} 季总 {no_exist.total_episode} 集"
            for sea, no_exist in season_map.items()
        ]

    @staticmethod
    def _should_auto_download(userid: Union[str, int]) -> bool:
        """
        判断当前用户是否命中自动下载名单。
        """
        auto_download_user = settings.AUTO_DOWNLOAD_USER
        return bool(
            auto_download_user
            and (
                auto_download_user == "all"
                or any(userid == user for user in auto_download_user.split(","))
            )
        )

    def _post_invalid_input(
        self,
        channel: MessageChannel,
        source: str,
        userid: Union[str, int],
        username: Optional[str],
        title: str = "输入有误！",
    ) -> None:
        """
        发送统一的非法输入提示。
        """
        self.post_message(
            Notification(
                channel=channel,
                source=source,
                userid=userid,
                username=username,
                title=title,
            )
        )
