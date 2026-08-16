from typing import Any, Optional, Tuple, Union

from app.domain.context import (
    MusicAlbumInfo,
    MusicArtistInfo,
    MusicInfo,
)
from app.domain.media import is_media_source_selected
from app.domain.meta.metabase import MetaBase
from app.domain.meta.metamusic import MetaMusic
from app.modules import _ModuleBase
from app.modules.recognizers.musicbrainz.api import MusicBrainzApi
from app.modules.recognizers.musicbrainz.mapping import (
    artist_to_info,
    info_from_meta,
    recording_to_info,
    related_artists,
    release_group_to_album,
    release_to_album,
    release_variants,
    select_track_release,
    track_to_info,
)
from app.modules.recognizers.musicbrainz.matching import (
    ALBUM_MATCH_THRESHOLD,
    build_query,
    interleave_results,
    match_text,
    release_track_summary,
    score_release,
    search_title,
    select_album_candidate,
    select_candidate,
    soundtrack_body,
    strip_artist_prefix,
    strip_parenthetical,
    strip_volume_suffix,
    unique_texts,
)
from app.modules.recognizers.musicbrainz.music_cache import MusicBrainzCache
from app.runtime.log import logger
from app.schemas.types import (
    MUSIC_ENTITY_ALBUM,
    MUSIC_ENTITY_RECORDING,
    MediaRecognizeType,
    MediaSource,
    MediaSourceSelection,
    MediaType,
    ModuleType,
)


class MusicBrainzModule(_ModuleBase):
    """通过 MusicBrainz 提供音乐元数据搜索和详情识别。"""

    _source = MediaSource.MusicBrainz
    # 本地识别缓存，由模块管理器初始化时挂载
    cache: MusicBrainzCache = None
    # MusicBrainz 接口客户端，由模块管理器初始化时挂载
    musicbrainzapi: MusicBrainzApi = None

    def init_module(self) -> None:
        """初始化 MusicBrainz 模块，挂载接口客户端与本地识别缓存。"""
        self.cache = MusicBrainzCache()
        self.musicbrainzapi = MusicBrainzApi()

    def init_setting(self) -> Optional[Tuple[str, Union[str, bool]]]:
        """MusicBrainz 无需独立密钥或启用开关。"""
        return None

    def stop(self) -> None:
        """停止模块，退出前持久化识别缓存并关闭接口客户端。"""
        if self.cache:
            try:
                self.cache.save()
            except Exception as err:
                logger.error(f"保存音乐识别缓存失败：{str(err)}")
        if self.musicbrainzapi:
            self.musicbrainzapi.close()

    def scheduler_job(self) -> None:
        """定时任务，每10分钟持久化一次音乐识别缓存。"""
        if self.cache:
            self.cache.save()

    def clear_cache(self) -> None:
        """响应全局缓存清理事件，清空音乐识别缓存。"""
        logger.info("开始清除音乐识别缓存 ...")
        if self.cache:
            self.cache.clear()
        logger.info("音乐识别缓存清除完成")

    def test(self) -> Tuple[bool, str]:
        """测试 MusicBrainz 搜索接口连通性。"""
        result = self.musicbrainzapi.request_json(
            "/recording",
            params={"query": "recording:test", "limit": 1, "fmt": "json"},
        )
        return (True, "") if result is not None else (False, "MusicBrainz 网络连接失败")

    @staticmethod
    def get_name() -> str:
        """返回模块展示名称。"""
        return "MusicBrainz"

    @staticmethod
    def get_music_source() -> MediaSource:
        """返回音乐识别使用的数据源标识。"""
        return MusicBrainzModule._source

    @staticmethod
    def get_type() -> ModuleType:
        """返回模块所属的媒体识别类型。"""
        return ModuleType.MediaRecognize

    @staticmethod
    def get_subtype() -> MediaRecognizeType:
        """返回 MusicBrainz 模块子类型。"""
        return MediaRecognizeType.MusicBrainz

    @staticmethod
    def get_priority() -> int:
        """音乐识别在所有 MediaRecognize 模块中最先响应，避免音乐请求被影视模块误识别。"""
        return 0

    def search_music(
            self,
            meta: MetaMusic,
            limit: int = 20,
            media_source: Optional[MediaSourceSelection] = None,
    ) -> Optional[list[MusicInfo]]:
        """搜索单曲、专辑和艺术家，并交错返回可浏览的 MusicBrainz 候选。"""
        if not is_media_source_selected(media_source, self._source):
            return None
        normalized_limit = max(1, min(limit, 100))
        recordings = self._search_recordings(meta, limit=normalized_limit)
        albums = self._search_albums(meta, limit=normalized_limit)
        artists = self._search_artists(meta, limit=normalized_limit)
        return interleave_results(
            recordings,
            albums,
            artists,
            limit=normalized_limit,
        )

    def _search_recordings(self, meta: MetaMusic, limit: int) -> list[MusicInfo]:
        """按音频标签条件搜索 Recording，供全局搜索和文件识别复用。"""
        for query in self._recording_queries(meta):
            payload = self.musicbrainzapi.request_json(
                "/recording",
                params={"query": query, "limit": max(1, min(limit, 100)), "fmt": "json"},
            )
            results = [
                info
                for item in (payload or {}).get("recordings") or []
                if (info := recording_to_info(item))
            ]
            if results:
                return results
        return []

    async def _async_search_recordings(
            self,
            meta: MetaMusic,
            limit: int,
    ) -> list[MusicInfo]:
        """异步按音频标签条件搜索 Recording 候选。"""
        for query in self._recording_queries(meta):
            payload = await self.musicbrainzapi.async_request_json(
                "/recording",
                params={
                    "query": query,
                    "limit": max(1, min(limit, 100)),
                    "fmt": "json",
                },
            )
            results = [
                info
                for item in (payload or {}).get("recordings") or []
                if (info := recording_to_info(item))
            ]
            if results:
                return results
        return []

    @classmethod
    def _recording_queries(cls, meta: MetaMusic) -> list[str]:
        """构造 Recording 检索式阶梯，由严到宽逐级放宽避免零命中。

        条目括号多为全角、艺术家署名存在变体（如外文艺名），精确 AND 条件容易零命中；
        放宽后由候选评分负责收紧（已知艺术家时必须艺术家命中），不会产生错误身份。
        """
        title = search_title(meta.title)
        if not title:
            return []
        artist = meta.artists[0] if meta.artists else None
        # 括号内的影视 tie-in、版本说明多为半角，与条目全角写法不一致，准备去注释曲名兜底
        bare_title = strip_parenthetical(title)
        # 曲名开头的艺术家署名前缀是命名习惯不是曲名内容，用主体名检索
        title = strip_artist_prefix(title, meta.artists)
        bare_title = strip_artist_prefix(bare_title, meta.artists)
        queries: list[str] = []
        for query in [
            build_query(meta),
            f"recording:{MusicBrainzApi.query_phrase(title)}" if title else None,
            f'recording:{MusicBrainzApi.query_phrase(bare_title)} AND artist:"{MusicBrainzApi.escape_query(artist)}"'
            if artist and bare_title and bare_title != title else None,
            # 艺术家署名变体（外文艺名等）导致 AND 条件零命中时，仅按主体曲名检索，
            # 候选挑选阶段要求艺术家命中兜住同名异曲
            f"recording:{MusicBrainzApi.query_phrase(bare_title)}" if bare_title else None,
        ]:
            if query and query not in queries:
                queries.append(query)
        return queries

    def _search_albums(self, meta: MetaMusic, limit: int) -> list[MusicInfo]:
        """按标题和可选艺术家搜索 Release Group 专辑候选，检索式同样逐级放宽。"""
        for query in self._album_queries(meta):
            payload = self.musicbrainzapi.request_json(
                "/release-group",
                params={
                    "query": query,
                    "limit": max(1, min(limit, 100)),
                    "fmt": "json",
                },
            )
            results = [
                album.to_music_info()
                for item in (payload or {}).get("release-groups") or []
                if (album := release_group_to_album(item))
            ]
            if results:
                return results
        return []

    async def _async_search_albums(
            self,
            meta: MetaMusic,
            limit: int,
    ) -> list[MusicInfo]:
        """异步按标题和可选艺术家搜索 Release Group 专辑候选。"""
        for query in self._album_queries(meta):
            payload = await self.musicbrainzapi.async_request_json(
                "/release-group",
                params={
                    "query": query,
                    "limit": max(1, min(limit, 100)),
                    "fmt": "json",
                },
            )
            results = [
                album.to_music_info()
                for item in (payload or {}).get("release-groups") or []
                if (album := release_group_to_album(item))
            ]
            if results:
                return results
        return []

    @classmethod
    def _album_queries(cls, meta: MetaMusic) -> list[str]:
        """构造专辑检索式阶梯：专辑名+艺术家 → 仅专辑名 → 去括号/卷号变体。"""
        title = search_title(meta.album or meta.title)
        if not title:
            return []
        artist = meta.artists[0] if meta.artists else None
        # 括号注释与 Vol. 卷号在条目中常以 disambiguation 形式存在，变体名兜底检索
        bare_title = strip_parenthetical(title)
        bare_title = strip_volume_suffix(bare_title)
        # 专辑名开头的艺术家署名前缀同样是命名习惯，用主体名检索
        title = strip_artist_prefix(title, meta.artists)
        bare_title = strip_artist_prefix(bare_title, meta.artists)
        # 原声带标题的通用描述词（Original Motion Picture Soundtrack）在条目中常省略，
        # 用电影名本体补充一级检索（The Hateful Eight / Pulp Fiction）；
        # 本体过短（The Score 类）时不作为独立检索目标避免噪声
        movie_name = soundtrack_body(bare_title)
        if len(match_text(movie_name)) < 4:
            movie_name = ""
        queries: list[str] = []
        for query in [
            f'releasegroup:{MusicBrainzApi.query_phrase(title)} AND artist:"{MusicBrainzApi.escape_query(artist)}"'
            if artist else None,
            f"releasegroup:{MusicBrainzApi.query_phrase(title)}" if title else None,
            f'releasegroup:{MusicBrainzApi.query_phrase(bare_title)} AND artist:"{MusicBrainzApi.escape_query(artist)}"'
            if artist and bare_title and bare_title != title else None,
            f'releasegroup:{MusicBrainzApi.query_phrase(movie_name)} AND artist:"{MusicBrainzApi.escape_query(artist)}"'
            if artist and movie_name else None,
            f"releasegroup:{MusicBrainzApi.query_phrase(movie_name)}" if movie_name else None,
            # 署名变体兜底：仅按去注释专辑名检索，挑选阶段要求艺术家同时命中
            f"releasegroup:{MusicBrainzApi.query_phrase(bare_title)}" if bare_title else None,
        ]:
            if query and query not in queries:
                queries.append(query)
        return queries

    def _search_artists(self, meta: MetaMusic, limit: int) -> list[MusicInfo]:
        """按用户输入中的艺术家部分搜索 Artist 浏览候选。"""
        artist_name = meta.artists[0] if meta.artists else meta.title
        phrase = MusicBrainzApi.query_phrase(artist_name)
        if not phrase:
            return []
        payload = self.musicbrainzapi.request_json(
            "/artist",
            params={"query": f"artist:{phrase}", "limit": max(1, min(limit, 100)), "fmt": "json"},
        )
        return [
            artist.to_music_info()
            for item in (payload or {}).get("artists") or []
            if (artist := artist_to_info(item, include_raw=True))
        ]

    def match_music_album(
            self,
            meta: MetaMusic,
            tracks: list[MetaMusic],
            limit: int = 5,
    ) -> Optional[MusicAlbumInfo]:
        """按目录线索和曲目特征把本地音频集合对位到 MusicBrainz 发行版本。

        适用于无标签整专目录：用专辑名、歌手搜索候选发行版本，再用曲目数、
        总时长和逐曲时长相似度打分，选出最可信的版本并返回其曲目表。
        """
        if not tracks:
            return None
        best_album: Optional[MusicAlbumInfo] = None
        best_score = 0.0
        for release in self._search_release_candidates(meta, tracks, limit=limit):
            release_id = release.get("id")
            if not release_id:
                continue
            detail = self.musicbrainzapi.request_json(
                f"/release/{release_id}",
                params={"inc": "recordings+media+artist-credits", "fmt": "json"},
            )
            if not detail:
                continue
            summary = release_track_summary(detail)
            score = score_release(meta, tracks, detail, summary)
            if score > best_score:
                best_score = score
                best_album = release_to_album(detail)
        # 得分低于阈值时宁可不匹配，避免把曲目写到错误的专辑上
        if best_score < ALBUM_MATCH_THRESHOLD:
            return None
        return best_album

    async def async_match_music_album(
            self,
            meta: MetaMusic,
            tracks: list[MetaMusic],
            limit: int = 5,
    ) -> Optional[MusicAlbumInfo]:
        """异步按目录线索和曲目特征匹配 MusicBrainz 发行版本。"""
        if not tracks:
            return None
        best_album: Optional[MusicAlbumInfo] = None
        best_score = 0.0
        releases = await self._async_search_release_candidates(
            meta,
            tracks,
            limit=limit,
        )
        for release in releases:
            release_id = release.get("id")
            if not release_id:
                continue
            detail = await self.musicbrainzapi.async_request_json(
                f"/release/{release_id}",
                params={"inc": "recordings+media+artist-credits", "fmt": "json"},
            )
            if not detail:
                continue
            summary = release_track_summary(detail)
            score = score_release(meta, tracks, detail, summary)
            if score > best_score:
                best_score = score
                best_album = release_to_album(detail)
        if best_score < ALBUM_MATCH_THRESHOLD:
            return None
        return best_album

    def _search_release_candidates(
            self,
            meta: MetaMusic,
            tracks: list[MetaMusic],
            limit: int,
    ) -> list[dict[str, Any]]:
        """按专辑名和曲名线索搜索候选发行版本，多个查询按命中顺序去重。"""
        releases: list[dict[str, Any]] = []
        seen: set[str] = set()
        for query in self._release_queries(meta, tracks):
            payload = self.musicbrainzapi.request_json(
                "/release",
                params={"query": query, "limit": max(1, min(limit, 25)), "fmt": "json"},
            )
            for item in (payload or {}).get("releases") or []:
                release_id = item.get("id")
                if release_id and release_id not in seen:
                    seen.add(release_id)
                    releases.append(item)
            if len(releases) >= limit:
                break
        return releases[:limit]

    async def _async_search_release_candidates(
            self,
            meta: MetaMusic,
            tracks: list[MetaMusic],
            limit: int,
    ) -> list[dict[str, Any]]:
        """异步按专辑名和曲名线索搜索并去重候选发行版本。"""
        releases: list[dict[str, Any]] = []
        seen: set[str] = set()
        for query in self._release_queries(meta, tracks):
            payload = await self.musicbrainzapi.async_request_json(
                "/release",
                params={
                    "query": query,
                    "limit": max(1, min(limit, 25)),
                    "fmt": "json",
                },
            )
            for item in (payload or {}).get("releases") or []:
                release_id = item.get("id")
                if release_id and release_id not in seen:
                    seen.add(release_id)
                    releases.append(item)
            if len(releases) >= limit:
                break
        return releases[:limit]

    @classmethod
    def _release_queries(cls, meta: MetaMusic, tracks: list[MetaMusic]) -> list[str]:
        """构造专辑搜索表达式：优先专辑名+歌手，无专辑线索时用曲名兜底。"""
        queries: list[str] = []
        album_title = meta.album or meta.title
        artist = meta.artists[0] if meta.artists else meta.album_artist
        if album_title:
            if artist:
                queries.append(
                    f'release:"{MusicBrainzApi.escape_query(album_title)}" AND artist:"{MusicBrainzApi.escape_query(artist)}"'
                )
            queries.append(f'release:"{MusicBrainzApi.escape_query(album_title)}"')
        # 目录名无意义时（如 Various Artists 合集），用代表性曲名反查所属发行版本
        titles = unique_texts(
            [track.title for track in tracks if track.title and not track.title.strip().isdigit()]
        )[:3]
        if titles:
            recording_clause = " OR ".join(
                f'recording:"{MusicBrainzApi.escape_query(title)}"' for title in titles
            )
            query = f"({recording_clause})"
            if artist:
                query += f' AND artist:"{MusicBrainzApi.escape_query(artist)}"'
            queries.append(query)
        return queries

    def recognize_media(
            self,
            meta: MetaBase = None,
            mtype: MediaType = None,
            media_source: Optional[MediaSource] = None,
            media_id: Optional[str] = None,
            **kwargs,
    ) -> Optional[MusicInfo]:
        """跟随统一媒体识别分发，仅在音乐类型请求下返回 MusicBrainz 识别结果。"""
        music_type = kwargs.get("music_type")
        # 显式选择其它音乐源时必须让出识别管线，且不能复用 MusicBrainz 缓存。
        if media_source and media_source != self._source:
            return None
        # 非音乐请求交给影视识别模块，不占用识别管线
        if not isinstance(meta, MetaMusic) and mtype != MediaType.MUSIC and media_source != self._source:
            return None
        # 无 MetaMusic 元数据时仅响应本数据源的详情识别请求
        if not isinstance(meta, MetaMusic):
            if media_source == self._source and media_id:
                detail_kwargs = (
                    {"music_type": music_type} if music_type is not None else {}
                )
                return self.recognize_music(
                    media_source, str(media_id), **detail_kwargs
                )
            return None
        # 显式身份只允许按该 ID 和实体类型读取，失败后不能按标题替换成其它目标。
        resolved_source = media_source or meta.media_source
        resolved_media_id = media_id or meta.media_id
        if resolved_source and resolved_media_id:
            detail_kwargs = (
                {"music_type": music_type} if music_type is not None else {}
            )
            info = self.recognize_music(
                resolved_source,
                str(resolved_media_id),
                **detail_kwargs,
            )
            if info:
                self._update_recognize_cache(meta, info)
            return info
        # 专辑名称识别不复用 Recording 缓存，避免同名实体互相覆盖。
        if music_type == MUSIC_ENTITY_ALBUM:
            albums = self._search_albums(meta, limit=10)
            return select_album_candidate(meta, albums)
        # 识别缓存命中直接响应，避免重复搜索占用 MusicBrainz 限流配额
        cache_enabled = bool(kwargs.get("cache", True))
        if cache_enabled and self.cache:
            cached_info = self.cache.get(meta)
            if cached_info:
                if cached_info.media_id:
                    logger.info(f"{meta.title} 使用音乐识别缓存：{cached_info.title}")
                else:
                    logger.info(f"{meta.title} 使用音乐识别缓存：无法识别")
                cached_info.recognize_cache_hit = True
                return cached_info
        # 无身份时按标题搜索并挑选可信候选，检索不到时返回元数据兑底
        # 文件识别只能从 Recording 中挑选，专辑或艺术家同名结果不能成为音轨身份。
        candidates = self._search_recordings(meta, limit=10)
        matched = select_candidate(meta, candidates, media_source=resolved_source or self._source)
        # 整专/单曲发行类资源在 Recording 检索无果时，回退按专辑实体识别；
        # 专辑挑选要求标题与艺术家同时命中，无艺术家线索时回退检索必然无果，
        # 直接跳过避免浪费限流配额（批量识别场景可减少约半数请求）
        if not matched and meta.artists and music_type != MUSIC_ENTITY_RECORDING:
            albums = self._search_albums(meta, limit=10)
            matched = select_album_candidate(meta, albums)
        result = matched or info_from_meta(meta)
        # 无远端身份的兑底结果同样入缓存，避免批量识别时反复搜索同一文件
        self._update_recognize_cache(meta, result)
        return result

    def _update_recognize_cache(self, meta: MetaMusic, info: Optional[MusicInfo]) -> None:
        """识别完成后把结果写入本地识别缓存，未挂载缓存时静默跳过。"""
        if self.cache:
            self.cache.update(meta, info)

    def update_recognize_cache(
            self,
            meta: MetaBase,
            mediainfo: MusicInfo,
    ) -> Optional[bool]:
        """回填音乐本地识别缓存，共享识别成功后避免重复回查。"""
        if not meta or not mediainfo:
            return None
        if not isinstance(meta, MetaMusic) or not isinstance(mediainfo, MusicInfo):
            return None
        if mediainfo.media_source != self._source:
            return None
        self._update_recognize_cache(meta, mediainfo)
        return True

    async def async_update_recognize_cache(
            self,
            meta: MetaBase,
            mediainfo: MusicInfo,
    ) -> Optional[bool]:
        """异步回填音乐本地识别缓存。"""
        return self.update_recognize_cache(meta=meta, mediainfo=mediainfo)

    async def async_recognize_media(
            self,
            meta: MetaBase = None,
            mtype: MediaType = None,
            media_source: Optional[MediaSource] = None,
            media_id: Optional[str] = None,
            **kwargs,
    ) -> Optional[MusicInfo]:
        """异步识别 MusicBrainz 音乐详情或按元数据匹配单曲。"""
        music_type = kwargs.get("music_type")
        if media_source and media_source != self._source:
            return None
        if not isinstance(meta, MetaMusic) and mtype != MediaType.MUSIC and media_source != self._source:
            return None
        if not isinstance(meta, MetaMusic):
            if media_source == self._source and media_id:
                return await self.async_recognize_music(
                    media_source,
                    str(media_id),
                    music_type=music_type,
                )
            return None
        resolved_source = media_source or meta.media_source
        resolved_media_id = media_id or meta.media_id
        if resolved_source and resolved_media_id:
            info = await self.async_recognize_music(
                resolved_source,
                str(resolved_media_id),
                music_type=music_type,
            )
            if info:
                self._update_recognize_cache(meta, info)
            return info
        if music_type == MUSIC_ENTITY_ALBUM:
            albums = await self._async_search_albums(meta, limit=10)
            return select_album_candidate(meta, albums)
        cache_enabled = bool(kwargs.get("cache", True))
        if cache_enabled and self.cache:
            cached_info = self.cache.get(meta)
            if cached_info:
                if cached_info.media_id:
                    logger.info(f"{meta.title} 使用音乐识别缓存：{cached_info.title}")
                else:
                    logger.info(f"{meta.title} 使用音乐识别缓存：无法识别")
                cached_info.recognize_cache_hit = True
                return cached_info
        candidates = await self._async_search_recordings(meta, limit=10)
        matched = select_candidate(
            meta,
            candidates,
            media_source=resolved_source or self._source,
        )
        if not matched and meta.artists and music_type != MUSIC_ENTITY_RECORDING:
            albums = await self._async_search_albums(meta, limit=10)
            matched = select_album_candidate(meta, albums)
        result = matched or info_from_meta(meta)
        self._update_recognize_cache(meta, result)
        return result

    def recognize_music(
            self,
            media_source: MediaSource,
            media_id: str,
            music_type: Optional[str] = None,
    ) -> Optional[MusicInfo]:
        """按 MusicBrainz 标准 ID 和实体类型获取详情；空类型保留旧版探测顺序。"""
        if media_source != self._source or not media_id:
            return None
        if music_type != MUSIC_ENTITY_ALBUM:
            payload = self.musicbrainzapi.request_json(
                f"/recording/{media_id}",
                params={
                    "inc": "artists+releases+release-groups+isrcs+genres",
                    "fmt": "json",
                },
            )
            if payload:
                return recording_to_info(payload)
            if music_type == MUSIC_ENTITY_RECORDING:
                return None
        # MusicBrainz 各实体共用 UUID 形式，统一详情入口在 Recording 未命中后继续探测专辑。
        album = self.music_album(media_source, media_id)
        return album.to_music_info() if album else None

    async def async_recognize_music(
            self,
            media_source: MediaSource,
            media_id: str,
            music_type: Optional[str] = None,
    ) -> Optional[MusicInfo]:
        """异步按 MusicBrainz 标准 ID 和实体类型获取详情。"""
        if media_source != self._source or not media_id:
            return None
        if music_type != MUSIC_ENTITY_ALBUM:
            payload = await self.musicbrainzapi.async_request_json(
                f"/recording/{media_id}",
                params={
                    "inc": "artists+releases+release-groups+isrcs+genres",
                    "fmt": "json",
                },
            )
            if payload:
                return recording_to_info(payload)
            if music_type == MUSIC_ENTITY_RECORDING:
                return None
        album = await self._async_music_album(media_source, media_id)
        return album.to_music_info() if album else None

    async def _async_music_album(
            self,
            media_source: MediaSource,
            media_id: str,
    ) -> Optional[MusicAlbumInfo]:
        """异步按 MusicBrainz Release Group ID 获取专辑详情及曲目。"""
        if media_source != self._source or not media_id:
            return None
        payload = await self.musicbrainzapi.async_request_json(
            f"/release-group/{media_id}",
            params={
                "inc": "artists+releases+media+genres+tags+ratings",
                "fmt": "json",
            },
        )
        if not payload:
            return None
        album = release_group_to_album(payload)
        if not album:
            return None
        album.releases = release_variants(payload.get("releases") or [])
        album.tracks = await self._async_album_tracks(
            album,
            payload.get("releases") or [],
        )
        return album

    def music_album(
            self,
            media_source: MediaSource,
            media_id: str,
    ) -> Optional[MusicAlbumInfo]:
        """按 MusicBrainz Release Group ID 获取标准化专辑详情及曲目。"""
        if media_source != self._source or not media_id:
            return None
        payload = self.musicbrainzapi.request_json(
            f"/release-group/{media_id}",
            params={
                "inc": "artists+releases+media+genres+tags+ratings",
                "fmt": "json",
            },
        )
        if not payload:
            return None
        album = release_group_to_album(payload)
        if not album:
            return None
        album.releases = release_variants(payload.get("releases") or [])
        album.tracks = self._album_tracks(album, payload.get("releases") or [])
        return album

    def music_artist(
            self,
            media_source: MediaSource,
            media_id: str,
    ) -> Optional[MusicArtistInfo]:
        """按 MusicBrainz Artist ID 获取标准化艺术家详情。"""
        if media_source != self._source or not media_id:
            return None
        payload = self.musicbrainzapi.request_json(
            f"/artist/{media_id}",
            params={"inc": "url-rels+genres+tags+aliases", "fmt": "json"},
        )
        return artist_to_info(payload) if payload else None

    def music_artist_albums(
            self,
            media_source: MediaSource,
            media_id: str,
            page: int = 1,
            count: int = 30,
            album_type: Optional[str] = None,
    ) -> list[MusicInfo]:
        """按 MusicBrainz Artist ID 分页浏览该艺术家的专辑、EP 和单曲。"""
        if media_source != self._source or not media_id:
            return []
        limit = max(1, min(count, 100))
        params: dict[str, Any] = {
            "artist": media_id,
            "inc": "artist-credits",
            "limit": limit,
            "offset": max(page - 1, 0) * limit,
            "fmt": "json",
        }
        if album_type:
            params["type"] = album_type
        payload = self.musicbrainzapi.request_json("/release-group", params=params)
        albums = [
            album
            for item in (payload or {}).get("release-groups") or []
            if (album := release_group_to_album(item))
        ]
        # MusicBrainz 浏览接口不支持排序，只能在当前页内按发行日期倒序，保证首页是最新作品
        albums.sort(key=lambda item: item.release_date or "", reverse=True)
        return [album.to_music_info() for album in albums]

    def music_artist_related(
            self,
            media_source: MediaSource,
            media_id: str,
            count: int = 24,
    ) -> list[MusicArtistInfo]:
        """按 MusicBrainz 艺术家关系返回可继续浏览的关联艺术家。"""
        if media_source != self._source or not media_id:
            return []
        payload = self.musicbrainzapi.request_json(
            f"/artist/{media_id}",
            params={"inc": "artist-rels", "fmt": "json"},
        )
        if not payload:
            return []
        return related_artists(payload.get("relations") or [], count=count)

    def _album_tracks(
            self,
            album: MusicAlbumInfo,
            releases: list[dict[str, Any]],
    ) -> list[MusicInfo]:
        """读取专辑代表性发行版本的曲目，作为专辑内音乐列表。"""
        release = select_track_release(releases)
        if not release.get("id"):
            return []
        payload = self.musicbrainzapi.request_json(
            f"/release/{release['id']}",
            params={"inc": "recordings+artist-credits", "fmt": "json"},
        )
        tracks: list[MusicInfo] = []
        for medium in (payload or {}).get("media") or []:
            for track in medium.get("tracks") or []:
                info = track_to_info(album, medium, track)
                if info:
                    tracks.append(info)
        return tracks

    async def _async_album_tracks(
            self,
            album: MusicAlbumInfo,
            releases: list[dict[str, Any]],
    ) -> list[MusicInfo]:
        """异步读取专辑代表性发行版本的曲目。"""
        release = select_track_release(releases)
        if not release.get("id"):
            return []
        payload = await self.musicbrainzapi.async_request_json(
            f"/release/{release['id']}",
            params={"inc": "recordings+artist-credits", "fmt": "json"},
        )
        tracks: list[MusicInfo] = []
        for medium in (payload or {}).get("media") or []:
            for track in medium.get("tracks") or []:
                info = track_to_info(album, medium, track)
                if info:
                    tracks.append(info)
        return tracks
