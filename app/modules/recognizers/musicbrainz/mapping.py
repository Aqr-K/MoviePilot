"""MusicBrainz 响应到领域对象的映射。

把 Web Service 返回的原始 JSON 翻译成 MusicInfo、MusicAlbumInfo、MusicArtistInfo 与
MusicRelease，涵盖字段取值与类型收敛、艺术家署名展开、封面与详情外链拼接，以及从
一组发行记录中挑出代表性版本。检索式构造、文本归一化与候选评分不在本模块。
"""
from typing import Any, Optional, Tuple

from app.domain.context import (
    MusicAlbumInfo,
    MusicArtistInfo,
    MusicInfo,
    MusicRelease,
)
from app.domain.meta.metamusic import MetaMusic
from app.runtime.config import settings
from app.schemas.types import MediaSource

# 条目详情页地址，用于给领域对象拼接可跳转的外部链接
_DETAIL_URL = "https://musicbrainz.org/recording"
_ALBUM_DETAIL_URL = "https://musicbrainz.org/release-group"
_ARTIST_DETAIL_URL = "https://musicbrainz.org/artist"
# 关联艺术家按关系可读性排序，纪念性质的致敬关系数量庞大且价值低，放到最后
_ARTIST_RELATION_PRIORITY = (
    "member of band",
    "subgroup",
    "collaboration",
    "founder",
    "artist rename",
    "supporting musician",
    "conductor position",
    "involved with",
    "teacher",
    "sibling",
    "parent",
    "married",
)
# 艺术家外链只保留对用户有意义的官方与流媒体入口
_ARTIST_LINK_TYPES = (
    "official homepage",
    "wikidata",
    "wikipedia",
    "discogs",
    "allmusic",
    "social network",
    "free streaming",
    "streaming",
    "youtube",
    "purchase for download",
)


def optional_int(value: Any) -> Optional[int]:
    """将 MusicBrainz 的碟号、音轨号等计数字段转换为可选整数。

    :param value: 原始计数字段
    :return: 整数值；缺失或无法解析时返回 None
    """
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def duration_seconds(value: Any) -> Optional[int]:
    """将 MusicBrainz 毫秒时长转换为整数秒。

    :param value: 毫秒时长
    :return: 秒数；缺失或无法解析时返回 None
    """
    try:
        return round(int(value) / 1000) if value is not None else None
    except (TypeError, ValueError):
        return None


def year(value: Optional[str]) -> Optional[int]:
    """从 MusicBrainz 的可变精度日期提取年份。

    :param value: 可变精度发行日期，可能只精确到年或年月
    :return: 年份；日期缺失或格式异常时返回 None
    """
    if not value:
        return None
    try:
        return int(value[:4])
    except (TypeError, ValueError):
        return None


def release_date(recording: dict[str, Any], release: dict[str, Any]) -> Optional[str]:
    """从录音和发行信息中选择最可靠的发行日期。

    :param recording: Recording 响应
    :param release: 该录音选定的 Release 响应
    :return: 发行日期；两者都缺失时返回 None
    """
    return recording.get("first-release-date") or release.get("date")


def date_sort_key(value: Optional[str]) -> tuple[int, str]:
    """将完整或不完整发行日期转换为稳定排序键。

    :param value: 发行日期
    :return: 排序键，无日期的记录排在有日期的之后
    """
    return (0, value) if value else (1, "")


def artist_credits(
        artist_credit: Optional[list[dict[str, Any]]],
) -> Tuple[list[str], list[str]]:
    """从 MusicBrainz artist-credit 提取有序艺术家名称和按位置对齐的标准 ID。

    :param artist_credit: artist-credit 列表
    :return: (艺术家名称列表, 与名称下标一一对应的艺术家 ID 列表)
    """
    names: list[str] = []
    ids: list[str] = []
    for credit in artist_credit or []:
        artist = credit.get("artist") or {}
        name = artist.get("name") or credit.get("name")
        if not name or str(name) in names:
            continue
        names.append(str(name))
        # 名称与 ID 按下标一一对应，缺少 ID 时补空串，前端据此决定是否可跳转
        ids.append(str(artist.get("id") or ""))
    return names, ids


def names_of(items: Optional[list[dict[str, Any]]]) -> list[str]:
    """提取 MusicBrainz 风格、标签或别名列表的名称，热度高的排在前面。

    :param items: 带 name 与 count 字段的条目列表
    :return: 按热度倒序、同热度按名称升序排列的名称列表
    """
    entries = [item for item in items or [] if item.get("name")]
    entries.sort(key=lambda item: (-int(item.get("count") or 0), str(item["name"])))
    return [str(item["name"]) for item in entries]


def build_cover_url(release_group_id: Optional[str]) -> Optional[str]:
    """根据 Release Group ID 构造 Cover Art Archive 封面地址。

    :param release_group_id: Release Group 标准 ID
    :return: 封面地址；无 ID 时返回 None
    """
    if not release_group_id:
        return None
    # 支持配置音乐封面代理地址，解决 coverartarchive.org 无法访问的问题
    base = (settings.MUSIC_COVER_PROXY or "https://coverartarchive.org").rstrip("/")
    return f"{base}/release-group/{release_group_id}/front-500"


def select_release(releases: list[dict[str, Any]]) -> dict[str, Any]:
    """优先选择正式且日期最早的发行记录。

    :param releases: 同一录音下的发行记录列表
    :return: 选中的发行记录；列表为空时返回空字典
    """
    if not releases:
        return {}
    official = [release for release in releases if release.get("status") == "Official"]
    candidates = official or releases
    return min(
        candidates,
        key=lambda release: date_sort_key(release.get("date")),
    )


def select_track_release(releases: list[dict[str, Any]]) -> dict[str, Any]:
    """选择曲目最完整且发行最早的正式版本，作为专辑曲目来源。

    :param releases: 同一专辑下的发行记录列表
    :return: 选中的发行记录；无可用记录时返回空字典
    """
    candidates = [
        release
        for release in releases
        if release.get("id")
        and sum(int(item.get("track-count") or 0) for item in release.get("media") or [])
    ]
    if not candidates:
        return next((release for release in releases if release.get("id")), {})
    official = [release for release in candidates if release.get("status") == "Official"]
    return min(
        official or candidates,
        key=lambda release: date_sort_key(release.get("date")),
    )


def release_variants(releases: list[dict[str, Any]]) -> list[MusicRelease]:
    """整理同一专辑下的发行版本，供详情页对比介质和地区。

    :param releases: Release 响应列表
    :return: 按日期与标题排序的发行版本列表
    """
    variants = []
    for release in releases:
        if not release.get("id"):
            continue
        media = release.get("media") or []
        variants.append(
            MusicRelease(
                media_id=str(release["id"]),
                title=release.get("title"),
                date=release.get("date") or None,
                country=release.get("country") or None,
                status=release.get("status") or None,
                packaging=release.get("packaging") or None,
                formats=[str(item["format"]) for item in media if item.get("format")],
                track_count=sum(int(item.get("track-count") or 0) for item in media) or None,
            )
        )
    variants.sort(key=lambda item: (date_sort_key(item.date), item.title or ""))
    return variants


def recording_to_info(recording: dict[str, Any]) -> Optional[MusicInfo]:
    """将 MusicBrainz Recording 响应转换为标准音乐信息。

    :param recording: Recording 响应
    :return: 标准音乐信息；缺少 ID 或标题时返回 None
    """
    media_id = recording.get("id")
    title = recording.get("title")
    if not media_id or not title:
        return None
    releases = recording.get("releases") or []
    release = select_release(releases)
    release_group = (release or {}).get("release-group") or {}
    resolved_date = release_date(recording, release)
    album = (release or {}).get("title")
    artists, artist_ids = artist_credits(recording.get("artist-credit"))
    album_artists, _ = artist_credits((release or {}).get("artist-credit"))
    category_parts = [release_group.get("primary-type")]
    category_parts.extend(release_group.get("secondary-types") or [])
    return MusicInfo(
        media_source=MediaSource.MusicBrainz,
        media_id=str(media_id),
        title=str(title),
        artists=artists,
        artist_ids=artist_ids,
        album=album,
        album_artist=" / ".join(album_artists) if album_artists else None,
        album_id=str(release_group["id"]) if release_group.get("id") else None,
        album_type=release_group.get("primary-type"),
        year=year(resolved_date),
        release_date=resolved_date,
        duration=duration_seconds(recording.get("length")),
        isrc=next(iter(recording.get("isrcs") or []), None),
        cover_url=build_cover_url(release_group.get("id")),
        version=recording.get("disambiguation") or None,
        category=" / ".join(str(part) for part in category_parts if part),
        genres=names_of(recording.get("genres")),
        names=[name for name in (title, album) if name],
        detail_link=f"{_DETAIL_URL}/{media_id}",
        raw_data=recording,
    )


def release_group_to_album(release_group: dict[str, Any]) -> Optional[MusicAlbumInfo]:
    """将 MusicBrainz Release Group 响应转换为标准专辑信息。

    :param release_group: Release Group 响应
    :return: 标准专辑信息；缺少 ID 或标题时返回 None
    """
    media_id = release_group.get("id")
    title = release_group.get("title")
    if not media_id or not title:
        return None
    artists, artist_ids = artist_credits(release_group.get("artist-credit"))
    rating = release_group.get("rating") or {}
    return MusicAlbumInfo(
        media_source=MediaSource.MusicBrainz,
        media_id=str(media_id),
        title=str(title),
        artists=artists,
        artist_ids=artist_ids,
        album_type=release_group.get("primary-type"),
        secondary_types=[str(item) for item in release_group.get("secondary-types") or []],
        release_date=release_group.get("first-release-date") or None,
        cover_url=build_cover_url(media_id),
        genres=names_of(release_group.get("genres")),
        tags=names_of(release_group.get("tags")),
        # MusicBrainz 评分是 5 分制，统一放大到与影视一致的 10 分制展示
        rating=round(float(rating["value"]) * 2, 1) if rating.get("value") else 0.0,
        rating_votes=rating.get("votes-count"),
        detail_link=f"{_ALBUM_DETAIL_URL}/{media_id}",
        raw_data=release_group,
    )


def release_to_album(detail: dict[str, Any]) -> Optional[MusicAlbumInfo]:
    """将 MusicBrainz Release 详情转换为带曲目表的标准化专辑信息。

    :param detail: Release 详情响应，需包含 media 与 recordings
    :return: 带曲目表的专辑信息；缺少 ID 或标题时返回 None
    """
    release_id = detail.get("id")
    title = detail.get("title")
    if not release_id or not title:
        return None
    release_group = detail.get("release-group") or {}
    group_id = release_group.get("id")
    artists, artist_ids = artist_credits(detail.get("artist-credit"))
    album = MusicAlbumInfo(
        media_source=MediaSource.MusicBrainz,
        # 优先使用 Release Group ID，与专辑详情和封面入口保持一致
        media_id=str(group_id or release_id),
        title=str(title),
        artists=artists,
        artist_ids=artist_ids,
        album_type=release_group.get("primary-type"),
        secondary_types=[str(item) for item in release_group.get("secondary-types") or []],
        release_date=detail.get("date") or None,
        cover_url=build_cover_url(group_id),
        genres=names_of(detail.get("genres")),
        detail_link=f"https://musicbrainz.org/release/{release_id}",
        raw_data={"release_id": str(release_id)},
    )
    album.tracks = [
        info
        for medium in detail.get("media") or []
        for track in medium.get("tracks") or []
        if (info := track_to_info(album, medium, track))
    ]
    return album


def track_to_info(
        album: MusicAlbumInfo,
        medium: dict[str, Any],
        track: dict[str, Any],
) -> Optional[MusicInfo]:
    """将发行版本中的单条曲目转换为可继续浏览的音乐信息。

    :param album: 曲目所属的专辑信息，用于补全曲目缺失的字段
    :param medium: 曲目所在的介质（碟）响应
    :param track: 曲目响应
    :return: 标准音乐信息；缺少录音 ID 或标题时返回 None
    """
    recording = track.get("recording") or {}
    media_id = recording.get("id")
    title = track.get("title") or recording.get("title")
    if not media_id or not title:
        return None
    artists, artist_ids = artist_credits(
        track.get("artist-credit") or recording.get("artist-credit")
    )
    return MusicInfo(
        media_source=MediaSource.MusicBrainz,
        media_id=str(media_id),
        title=str(title),
        artists=artists or list(album.artists),
        artist_ids=artist_ids or list(album.artist_ids),
        album=album.title,
        album_artist=album.artist or None,
        album_id=album.media_id,
        album_type=album.album_type,
        year=album.year,
        release_date=recording.get("first-release-date") or album.release_date,
        disc_number=optional_int(medium.get("position")),
        track_number=optional_int(track.get("position")),
        total_tracks=optional_int(medium.get("track-count")),
        duration=duration_seconds(track.get("length") or recording.get("length")),
        cover_url=album.cover_url,
        version=recording.get("disambiguation") or None,
        category=album.category,
        names=[str(title)],
        detail_link=f"{_DETAIL_URL}/{media_id}",
    )


def artist_image(relations: list[dict[str, Any]]) -> Optional[str]:
    """从艺术家 image 关系解析可直接展示的图片地址。

    :param relations: 艺术家关系列表
    :return: 图片直链；无 image 关系时返回 None
    """
    for relation in relations:
        if relation.get("type") != "image":
            continue
        resource = (relation.get("url") or {}).get("resource") or ""
        # MusicBrainz 记录的是维基共享资源页地址，需要转成文件直链才能展示
        if "commons.wikimedia.org/wiki/File:" in resource:
            file_name = resource.rsplit("File:", 1)[-1]
            return (
                "https://commons.wikimedia.org/wiki/Special:FilePath/"
                f"{file_name}?width=500"
            )
        if resource:
            return resource
    return None


def artist_links(relations: list[dict[str, Any]]) -> dict[str, str]:
    """整理艺术家可对外跳转的官方与流媒体链接。

    :param relations: 艺术家关系列表
    :return: 关系类型到链接地址的映射
    """
    links: dict[str, str] = {}
    for relation in relations:
        relation_type = str(relation.get("type") or "")
        resource = (relation.get("url") or {}).get("resource")
        if relation_type in _ARTIST_LINK_TYPES and resource:
            links.setdefault(relation_type, str(resource))
    return links


def artist_to_info(
        artist: dict[str, Any],
        relation: Optional[str] = None,
        include_raw: bool = False,
) -> Optional[MusicArtistInfo]:
    """将 MusicBrainz Artist 响应转换为标准艺术家信息。

    :param artist: Artist 响应
    :param relation: 与来源艺术家的关系类型
    :param include_raw: 是否保留原始响应，供搜索候选继续加工
    :return: 标准艺术家信息；缺少 ID 或名称时返回 None
    """
    media_id = artist.get("id")
    name = artist.get("name")
    if not media_id or not name:
        return None
    life_span = artist.get("life-span") or {}
    area = artist.get("area") or {}
    begin_area = artist.get("begin-area") or {}
    relations = artist.get("relations") or []
    return MusicArtistInfo(
        media_source=MediaSource.MusicBrainz,
        media_id=str(media_id),
        name=str(name),
        sort_name=artist.get("sort-name") or None,
        disambiguation=artist.get("disambiguation") or None,
        artist_type=artist.get("type") or None,
        gender=artist.get("gender") or None,
        country=artist.get("country") or None,
        area=area.get("name") or begin_area.get("name") or None,
        begin_date=life_span.get("begin") or None,
        end_date=life_span.get("end") or None,
        ended=bool(life_span.get("ended")),
        genres=names_of(artist.get("genres")),
        tags=names_of(artist.get("tags")),
        aliases=names_of(artist.get("aliases")),
        relation=relation,
        image_url=artist_image(relations),
        detail_link=f"{_ARTIST_DETAIL_URL}/{media_id}",
        external_links=artist_links(relations),
        raw_data=artist if include_raw else {},
    )


def related_artists(
        relations: list[dict[str, Any]],
        count: int,
) -> list[MusicArtistInfo]:
    """按关系类型优先级整理关联艺术家，并按来源去重。

    :param relations: 艺术家关系列表
    :param count: 返回条数上限
    :return: 按关系优先级与名称排序的关联艺术家列表
    """
    ranked: list[tuple[int, MusicArtistInfo]] = []
    seen: set[str] = set()
    fallback_priority = len(_ARTIST_RELATION_PRIORITY)
    for relation in relations:
        if relation.get("target-type") != "artist":
            continue
        artist = relation.get("artist") or {}
        artist_id = str(artist.get("id") or "")
        if not artist_id or artist_id in seen:
            continue
        relation_type = str(relation.get("type") or "")
        info = artist_to_info(artist, relation=relation_type or None)
        if not info:
            continue
        seen.add(artist_id)
        priority = (
            _ARTIST_RELATION_PRIORITY.index(relation_type)
            if relation_type in _ARTIST_RELATION_PRIORITY
            else fallback_priority
        )
        ranked.append((priority, info))
    ranked.sort(key=lambda item: (item[0], item[1].name or ""))
    return [info for _, info in ranked[: max(1, count)]]


def info_from_meta(meta: MetaMusic) -> MusicInfo:
    """音乐识别无候选时，把元数据转换为可展示的最小信息。

    :param meta: 本地音频元数据
    :return: 由元数据构造的音乐信息
    """
    return MusicInfo.from_meta(meta)
