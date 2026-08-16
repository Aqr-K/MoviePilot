import re
from typing import Any, List, Optional, Tuple, Union

from app.domain.context import (
    MediaInfo,
    MusicAlbumInfo,
    MusicInfo,
)
from app.domain.meta.metabase import MetaBase
from app.domain.meta.metamusic import MetaMusic
from app.modules import _ModuleBase
from app.modules.recognizers.douban.apiv2 import DoubanApi
from app.schemas.types import (
    MUSIC_ENTITY_ALBUM,
    MUSIC_ENTITY_RECORDING,
    MediaSource,
    MediaSourceSelection,
    MediaType,
    ModuleType,
    MediaRecognizeType,
)
from app.adapters.network.http import RequestUtils
from app.domain.media import is_media_source_selected


class DoubanMusicModule(_ModuleBase):
    """提供豆瓣音乐的识别、专辑与曲目检索能力。"""

    _music_source = MediaSource.DoubanMusic
    doubanapi: DoubanApi = None

    def init_module(self) -> None:
        """建立豆瓣接口客户端"""
        self.doubanapi = DoubanApi()

    def stop(self):
        """关闭豆瓣接口客户端"""
        self.doubanapi.close()

    def test(self) -> Tuple[bool, str]:
        """
        测试模块连接性

        :return: (是否连通, 错误信息)
        """
        ret = RequestUtils().get_res("https://music.douban.com/")
        if ret is None:
            return False, "豆瓣音乐网络连接失败"
        return True, ""

    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        """模块开关，豆瓣音乐不受开关控制"""
        pass

    @staticmethod
    def get_name() -> str:
        """模块名称"""
        return "豆瓣音乐"

    @staticmethod
    def get_type() -> ModuleType:
        """
        获取模块类型
        """
        return ModuleType.MediaRecognize

    @staticmethod
    def get_subtype() -> MediaRecognizeType:
        """
        获取模块子类型
        """
        return MediaRecognizeType.DoubanMusic

    @staticmethod
    def get_priority() -> int:
        """
        获取模块优先级，数字越小优先级越高，只有同一接口下优先级才生效
        """
        return 2

    def recognize_media(self, meta: MetaBase = None,
                        mtype: MediaType = None,
                        media_source: Optional[MediaSource] = None,
                        media_id: Optional[str] = None,
                        **kwargs) -> Optional[MediaInfo]:
        """
        识别媒体信息，只处理豆瓣音乐来源

        :param meta: 识别的元数据
        :param mtype: 识别的媒体类型
        :param media_source: 媒体来源
        :param media_id: 媒体来源原生ID
        :return: 识别的媒体信息
        """
        if media_source != self._music_source:
            return None
        return self._recognize_music_media(
            meta=meta if isinstance(meta, MetaMusic) else None,
            media_source=media_source,
            media_id=media_id,
            music_type=kwargs.get("music_type"),
        )

    async def async_recognize_media(self, meta: MetaBase = None,
                                    mtype: MediaType = None,
                                    media_source: Optional[MediaSource] = None,
                                    media_id: Optional[str] = None,
                                    **kwargs) -> Optional[MediaInfo]:
        """
        识别媒体信息（异步版本），只处理豆瓣音乐来源

        :param meta: 识别的元数据
        :param mtype: 识别的媒体类型
        :param media_source: 媒体来源
        :param media_id: 媒体来源原生ID
        :return: 识别的媒体信息
        """
        if media_source != self._music_source:
            return None
        return await self._async_recognize_music_media(
            meta=meta if isinstance(meta, MetaMusic) else None,
            media_source=media_source,
            media_id=media_id,
            music_type=kwargs.get("music_type"),
        )

    @staticmethod
    def get_music_source() -> MediaSource:
        """返回音乐识别使用的数据源标识。"""
        return DoubanMusicModule._music_source

    def search_music(
            self,
            meta: MetaMusic,
            limit: int = 20,
            media_source: Optional[MediaSourceSelection] = None,
    ) -> Optional[List[MusicInfo]]:
        """按请求来源搜索豆瓣音乐专辑，并转换为统一音乐候选。"""
        if not is_media_source_selected(media_source, self._music_source):
            return None
        keyword = meta.album or meta.title
        if not keyword:
            return []
        result = self.doubanapi.music_search(keyword=keyword, count=max(1, min(limit, 100)))
        return self._build_music_search_results(result)

    def recognize_music(
            self,
            media_source: MediaSource,
            media_id: str,
            music_type: Optional[str] = None,
    ) -> Optional[MusicInfo]:
        """按豆瓣音乐原生 ID 和实体类型获取专辑或专辑内曲目详情。"""
        if media_source != self._music_source or not media_id:
            return None
        album_id, separator, track_id = str(media_id).partition(":")
        if music_type == MUSIC_ENTITY_RECORDING and not separator:
            return None
        if music_type == MUSIC_ENTITY_ALBUM and separator:
            return None
        album = self.music_album(media_source, album_id)
        if not album:
            return None
        if separator and track_id:
            return next(
                (
                    track for track in album.tracks
                    if track.media_id == media_id or str(track.track_number or "") == track_id
                ),
                None,
            )
        return album.to_music_info()

    def music_album(
            self,
            media_source: MediaSource,
            media_id: str,
    ) -> Optional[MusicAlbumInfo]:
        """按豆瓣音乐专辑 ID 获取标准化专辑详情和曲目。"""
        if media_source != self._music_source or not media_id:
            return None
        info = self.doubanapi.music_detail(subject_id=str(media_id))
        return self._douban_music_to_album(info) if info else None

    def music_discover(
            self,
            media_source: MediaSource,
            page: int = 1,
            count: int = 30,
            entity: str = MUSIC_ENTITY_ALBUM,
            mode: str = "chart",
            tags: str = "",
            sort: str = "U",
    ) -> Optional[List[MusicInfo]]:
        """按官方新碟榜或标签交集浏览豆瓣音乐，并保留豆瓣条目原生身份。"""
        if media_source != self._music_source:
            return None
        del entity
        if mode == "chart":
            chart_items = self._build_music_search_results(self.doubanapi.music_chart())
            start = max(page - 1, 0) * max(1, count)
            return chart_items[start:start + max(1, count)]
        selected_tags = [tag.strip() for tag in str(tags or "").split(",") if tag.strip()]
        if not selected_tags:
            selected_tags = ["流行"]
        if len(selected_tags) == 1:
            result = self.doubanapi.music_tag(
                tag=selected_tags[0],
                start=max(page - 1, 0) * max(1, count),
                count=max(1, count),
                sort=sort,
            )
            return self._build_music_search_results(result)

        # 豆瓣官网的多标签 URL 会按完整文本标签匹配；分别读取后按原生 ID
        # 求交集，才能实现风格与地区的真实组合筛选。
        scan_count = min(max(page * count * 4, 100), 300)
        tag_results = [
            self._build_music_search_results(
                self.doubanapi.music_tag(tag=tag, start=0, count=scan_count, sort=sort)
            )
            for tag in selected_tags
        ]
        if not tag_results:
            return []
        shared_ids = set(item.media_id for item in tag_results[0])
        for items in tag_results[1:]:
            shared_ids.intersection_update(item.media_id for item in items)
        matched = [item for item in tag_results[0] if item.media_id in shared_ids]
        start = max(page - 1, 0) * max(1, count)
        return matched[start:start + max(1, count)]

    def music_album_related(
            self,
            media_source: MediaSource,
            media_id: str,
            count: int = 24,
    ) -> Optional[List[MusicInfo]]:
        """按豆瓣音乐专辑 ID 返回相关推荐条目。"""
        if media_source != self._music_source or not media_id:
            return None
        result = self.doubanapi.music_recommendations(
            subject_id=str(media_id),
            start=0,
            count=max(1, count),
        )
        return self._build_music_search_results(result)

    def _recognize_music_media(
            self,
            meta: Optional[MetaMusic],
            media_source: Optional[MediaSource],
            media_id: Optional[str],
            music_type: Optional[str] = None,
    ) -> Optional[MusicInfo]:
        """执行豆瓣音乐详情识别或按专辑名称匹配。"""
        if media_source != self._music_source:
            return None
        resolved_media_id = media_id or (meta.media_id if meta else None)
        if resolved_media_id:
            detail_kwargs = (
                {"music_type": music_type} if music_type is not None else {}
            )
            return self.recognize_music(
                media_source, str(resolved_media_id), **detail_kwargs
            )
        if not meta:
            return None
        candidates = self.search_music(meta=meta, limit=20, media_source=media_source) or []
        expected_title = meta.album or meta.title
        for candidate in candidates:
            if not self._same_music_text(expected_title, candidate.title):
                continue
            if meta.artists and candidate.artists and not any(
                self._same_music_text(expected, actual)
                for expected in meta.artists
                for actual in candidate.artists
            ):
                continue
            if music_type == MUSIC_ENTITY_ALBUM:
                return candidate
            if meta.album and meta.title:
                album = self.music_album(media_source, candidate.media_id)
                matched_track = self._select_douban_music_track(meta, album)
                if matched_track:
                    return matched_track
                continue
            if music_type == MUSIC_ENTITY_RECORDING:
                continue
            return candidate
        return None

    async def _async_recognize_music_media(
            self,
            meta: Optional[MetaMusic],
            media_source: Optional[MediaSource],
            media_id: Optional[str],
            music_type: Optional[str] = None,
    ) -> Optional[MusicInfo]:
        """异步执行豆瓣音乐详情识别或按专辑名称匹配。"""
        if media_source != self._music_source:
            return None
        resolved_media_id = media_id or (meta.media_id if meta else None)
        if resolved_media_id:
            album_id, separator, track_id = str(resolved_media_id).partition(":")
            if music_type == MUSIC_ENTITY_RECORDING and not separator:
                return None
            if music_type == MUSIC_ENTITY_ALBUM and separator:
                return None
            info = await self.doubanapi.async_music_detail(subject_id=album_id)
            album = self._douban_music_to_album(info) if info else None
            if not album:
                return None
            if separator and track_id:
                return next(
                    (
                        track for track in album.tracks
                        if track.media_id == resolved_media_id
                        or str(track.track_number or "") == track_id
                    ),
                    None,
                )
            return album.to_music_info()
        if not meta:
            return None
        keyword = meta.album or meta.title
        if not keyword:
            return None
        result = await self.doubanapi.async_music_search(keyword=keyword, count=20)
        candidates = self._build_music_search_results(result)
        expected_title = meta.album or meta.title
        for candidate in candidates:
            if not self._same_music_text(expected_title, candidate.title):
                continue
            if meta.artists and candidate.artists and not any(
                self._same_music_text(expected, actual)
                for expected in meta.artists
                for actual in candidate.artists
            ):
                continue
            if music_type == MUSIC_ENTITY_ALBUM:
                return candidate
            if meta.album and meta.title:
                info = await self.doubanapi.async_music_detail(
                    subject_id=str(candidate.media_id)
                )
                album = self._douban_music_to_album(info) if info else None
                matched_track = self._select_douban_music_track(meta, album)
                if matched_track:
                    return matched_track
                continue
            if music_type == MUSIC_ENTITY_RECORDING:
                continue
            return candidate
        return None

    @classmethod
    def _select_douban_music_track(
            cls,
            meta: MetaMusic,
            album: Optional[MusicAlbumInfo],
    ) -> Optional[MusicInfo]:
        """从豆瓣专辑曲目中选择与本地曲名、艺术家及曲序最一致的音轨。"""
        if not album:
            return None
        candidates = [
            track for track in album.tracks
            if cls._same_music_text(meta.title, track.title)
        ]
        if meta.artists:
            candidates = [
                track for track in candidates
                if any(
                    cls._same_music_text(expected, actual)
                    for expected in meta.artists
                    for actual in track.artists
                )
            ]
        if not candidates:
            return None
        candidates.sort(
            key=lambda track: (
                bool(meta.track_number and track.track_number == meta.track_number),
                -abs((meta.duration or track.duration or 0) - (track.duration or meta.duration or 0)),
            ),
            reverse=True,
        )
        return candidates[0]

    @classmethod
    def _build_music_search_results(
            cls,
            result: Optional[dict | list],
    ) -> List[MusicInfo]:
        """把豆瓣音乐搜索响应转换为专辑候选列表。"""
        payload = result or {}
        if isinstance(payload, list):
            items = payload
        else:
            items = (
                payload.get("subject_collection_items")
                or payload.get("recommendations")
                or payload.get("subjects")
                or payload.get("items")
                or payload.get("musics")
                or []
            )
        candidates = []
        for item in items:
            if not isinstance(item, dict):
                continue
            target_type = str(item.get("target_type") or "").casefold()
            if isinstance(item.get("target"), dict):
                target = item["target"]
            elif isinstance(item.get("subject"), dict):
                target = item["subject"]
            else:
                target = item
            type_name = str(target.get("type_name") or target.get("subtype") or "")
            target_subject_type = str(target.get("type") or "").casefold()
            if target_type and target_type not in {"music", "音乐", "subject"}:
                continue
            if target_subject_type and target_subject_type not in {"music", "音乐"}:
                continue
            if type_name and type_name not in {"音乐", "music"}:
                continue
            media_id = cls._douban_music_text(
                target.get("id") or item.get("target_id") or item.get("id")
            )
            title = cls._douban_music_text(target.get("title") or target.get("name"))
            if not media_id or not title:
                continue
            artists = cls._douban_music_search_artists(target)
            release_date = cls._douban_music_date(target)
            cover_url = cls._douban_music_cover(target)
            candidate = MusicInfo(
                media_source=cls._music_source,
                media_id=media_id,
                music_type=MUSIC_ENTITY_ALBUM,
                title=title,
                artists=artists,
                album=title,
                album_artist=" / ".join(artists) or None,
                album_id=media_id,
                year=cls._douban_music_year(target.get("year") or release_date),
                release_date=release_date,
                cover_url=cover_url,
                names=[title],
                detail_link=f"https://music.douban.com/subject/{media_id}/",
                raw_data={
                    "rating": cls._douban_music_float(target["rating"].get("value")),
                    "rating_votes": cls._douban_music_int(target["rating"].get("count")),
                } if isinstance(target.get("rating"), dict) else {},
            )
            candidates.append(candidate)
        return candidates

    @classmethod
    def _douban_music_to_album(cls, info: dict[str, Any]) -> Optional[MusicAlbumInfo]:
        """把豆瓣音乐详情转换为标准专辑信息和曲目。"""
        media_id = cls._douban_music_text(info.get("id") or info.get("subject_id"))
        title = cls._douban_music_text(info.get("title") or info.get("name"))
        if not media_id or not title:
            return None
        attrs = info.get("attrs") if isinstance(info.get("attrs"), dict) else {}
        artists = cls._douban_music_artists(info)
        release_date = cls._douban_music_date(info)
        tags = [
            cls._douban_music_text(item.get("name") if isinstance(item, dict) else item)
            for item in (info.get("tags") or [])
        ]
        genres = [str(item) for item in info.get("genres") or [] if item]
        rating = info.get("rating") if isinstance(info.get("rating"), dict) else {}
        album = MusicAlbumInfo(
            media_source=cls._music_source,
            media_id=media_id,
            title=title,
            artists=artists,
            album_type=cls._douban_music_first(
                info.get("media") or attrs.get("media")
            ) or "Album",
            release_date=release_date,
            cover_url=cls._douban_music_cover(info),
            genres=genres,
            tags=[item for item in tags if item],
            rating=cls._douban_music_float(rating.get("value") or rating.get("average")),
            rating_votes=cls._douban_music_int(
                rating.get("count") or rating.get("numRaters") or info.get("ratings_count")
            ),
            detail_link=f"https://music.douban.com/subject/{media_id}/",
            raw_data={
                "overview": cls._douban_music_text(info.get("intro") or info.get("summary")),
                "publisher": cls._douban_music_first(
                    info.get("publisher") or attrs.get("publisher")
                ),
            },
        )
        album.tracks = cls._douban_music_tracks(info, album)
        return album

    @classmethod
    def _douban_music_tracks(
            cls,
            info: dict[str, Any],
            album: MusicAlbumInfo,
    ) -> List[MusicInfo]:
        """从豆瓣新旧响应结构中提取专辑曲目。"""
        attrs = info.get("attrs") if isinstance(info.get("attrs"), dict) else {}
        # Frodo 当前音乐详情使用 songs；tracks/attrs.tracks 兼容旧接口响应。
        tracks = info.get("songs") or info.get("tracks") or attrs.get("tracks") or []
        if isinstance(tracks, str):
            tracks = tracks.splitlines()
        elif not isinstance(tracks, list):
            tracks = []
        elif len(tracks) == 1 and isinstance(tracks[0], str) and "\n" in tracks[0]:
            tracks = tracks[0].splitlines()
        results = []
        for index, item in enumerate(tracks, start=1):
            if isinstance(item, dict):
                title = cls._douban_music_text(item.get("title") or item.get("name"))
                track_number = cls._douban_music_int(item.get("track_number") or item.get("position")) or index
                duration = cls._douban_music_int(item.get("duration"))
                duration = duration if duration and duration > 0 else None
                disc_number = cls._douban_music_int(
                    item.get("disc_number") or item.get("disc")
                )
                artists = cls._douban_music_artists(item) or list(album.artists)
                cover_url = cls._douban_music_text(item.get("cover_url")) or album.cover_url
                raw_data = {
                    key: value
                    for key, value in {
                        "apple_album_id": item.get("apple_album_id"),
                        "apple_track_id": item.get("apple_track_id"),
                        "preview_url": item.get("preview_url"),
                    }.items()
                    if value not in (None, "")
                }
            else:
                title = cls._clean_douban_track_title(item)
                track_number = index
                duration = None
                disc_number = None
                artists = list(album.artists)
                cover_url = album.cover_url
                raw_data = {}
            if not title:
                continue
            results.append(MusicInfo(
                media_source=cls._music_source,
                # 豆瓣歌曲没有独立 subject ID，使用专辑内绝对顺序避免多碟曲序重复。
                media_id=f"{album.media_id}:{index}",
                title=title,
                artists=artists,
                album=album.title,
                album_artist=album.artist or None,
                album_id=album.media_id,
                album_type=album.album_type,
                year=album.year,
                release_date=album.release_date,
                disc_number=disc_number,
                track_number=track_number,
                duration=duration,
                cover_url=cover_url,
                genres=list(album.genres),
                names=[title],
                detail_link=album.detail_link,
                raw_data=raw_data,
            ))
        for track in results:
            track.total_tracks = len(results)
        return results

    @classmethod
    def _douban_music_artists(cls, info: dict[str, Any]) -> List[str]:
        """从豆瓣新旧响应结构中提取艺术家名称。"""
        attrs = info.get("attrs") if isinstance(info.get("attrs"), dict) else {}
        values = (
            info.get("artists")
            or info.get("artist_names")
            or info.get("author")
            or info.get("singer")
            or attrs.get("singer")
            or []
        )
        if isinstance(values, str):
            values = [values]
        artists = []
        seen = set()
        for item in values:
            value = item.get("name") if isinstance(item, dict) else item
            text = cls._douban_music_text(value)
            identity = MetaMusic.compact_text(text) if text else ""
            if not text or identity in seen:
                continue
            seen.add(identity)
            artists.append(text)
        return artists

    @classmethod
    def _douban_music_search_artists(cls, info: dict[str, Any]) -> List[str]:
        """提取搜索候选艺术家，缺少结构化字段时回退到卡片副标题首段。"""
        artists = cls._douban_music_artists(info)
        if artists:
            return artists
        subtitle = cls._douban_music_text(info.get("card_subtitle"))
        if not subtitle:
            return []
        artist = re.split(r"\s+/\s+", subtitle, maxsplit=1)[0].strip()
        if not artist or re.fullmatch(r"\d{4}(?:-\d{1,2}(?:-\d{1,2})?)?", artist):
            return []
        return [artist]

    @classmethod
    def _douban_music_cover(cls, info: dict[str, Any]) -> Optional[str]:
        """从豆瓣多种图片字段中提取清晰封面。"""
        pic = info.get("pic") if isinstance(info.get("pic"), dict) else {}
        cover = info.get("cover") if isinstance(info.get("cover"), dict) else {}
        cover_img = info.get("cover_img") if isinstance(info.get("cover_img"), dict) else {}
        return next(
            (
                text for value in [
                    pic.get("large"),
                    cover_img.get("url"),
                    cover.get("large"),
                    cover.get("normal"),
                    cover.get("url"),
                    info.get("cover_url"),
                    info.get("image"),
                ]
                if (text := cls._douban_music_text(value))
            ),
            None,
        )

    @classmethod
    def _douban_music_date(cls, info: dict[str, Any]) -> Optional[str]:
        """从豆瓣新旧响应结构中提取首个发行日期。"""
        attrs = info.get("attrs") if isinstance(info.get("attrs"), dict) else {}
        return cls._douban_music_first(info.get("pubdate") or attrs.get("pubdate"))

    @staticmethod
    def _clean_douban_track_title(value: Any) -> Optional[str]:
        """清理豆瓣旧接口曲目文本开头的序号。"""
        text = str(value or "").strip()
        return re.sub(r"^\s*(?:\d+[\.、)]\s*)", "", text) or None

    @staticmethod
    def _douban_music_text(value: Any) -> Optional[str]:
        """把豆瓣外部响应值转换为去空白文本。"""
        text = str(value).strip() if value is not None else ""
        return text or None

    @classmethod
    def _douban_music_first(cls, value: Any) -> Optional[str]:
        """从豆瓣列表或标量字段中提取首个文本。"""
        if isinstance(value, list):
            return next((text for item in value if (text := cls._douban_music_text(item))), None)
        return cls._douban_music_text(value)

    @staticmethod
    def _douban_music_int(value: Any) -> Optional[int]:
        """将豆瓣外部响应值安全转换为整数。"""
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _douban_music_float(value: Any) -> float:
        """将豆瓣外部评分安全转换为浮点数。"""
        try:
            return float(value) if value not in (None, "") else 0.0
        except (TypeError, ValueError):
            return 0.0

    @classmethod
    def _douban_music_year(cls, value: Any) -> Optional[int]:
        """从豆瓣年份或日期文本中提取四位年份。"""
        text = cls._douban_music_text(value)
        return int(text[:4]) if text and text[:4].isdigit() else None

    @staticmethod
    def _same_music_text(left: Optional[str], right: Optional[str]) -> bool:
        """使用音乐元数据紧凑文本规则比较豆瓣候选。"""
        return bool(left and right and MetaMusic.compact_text(left) == MetaMusic.compact_text(right))
