"""
媒体端点的 Chain 编排（service layer）。

模糊搜索（MediaChain 按 media/collection/person 分支检索 + 按 SEARCH_SOURCE 排序 +
分页）与刮削（MediaChain 识别 + 本地路径校验 + scrape_metadata）。从端点下沉到服务层：
端点退化为薄 HTTP 适配层；本层可通过 mock MediaChain 单测。
"""
from pathlib import Path
from typing import List, Optional, Tuple, Union
from uuid import UUID

from app import schemas
from app.chain.media import MediaChain
from app.chain.scraping import ScrapingChain
from app.core.config import settings
from app.core.metainfo import MetaInfoPath
from app.core.context import MusicInfo
from app.schemas import MediaType
from app.schemas.types import MediaSource
from app.schemas.types import MUSIC_ENTITY_RECORDING
from app.utils.media import (
    is_music_media_source,
    normalize_media_source,
    parse_media_source_selection,
    normalize_music_type,
    resolve_media_identity,
)


def _is_valid_source_media_id(
        media_source: Optional[MediaSource], media_id: str,
) -> bool:
    """按媒体数据源校验原生 ID，并兼容豆瓣音乐的曲目复合 ID。"""
    normalized_source, normalized_media_id = resolve_media_identity(
        media_source=media_source,
        media_id=media_id,
    )
    if not normalized_source or not normalized_media_id:
        return False
    if normalized_source == MediaSource.MusicBrainz:
        try:
            UUID(normalized_media_id)
            return True
        except (TypeError, ValueError):
            return False
    if normalized_source == MediaSource.DoubanMusic and ":" in normalized_media_id:
        album_id, track_number = normalized_media_id.split(":", 1)
        return album_id.isdigit() and track_number.isdigit()
    if normalized_source == MediaSource.IMDb:
        return (
            normalized_media_id.startswith("tt")
            and normalized_media_id[2:].isdigit()
        )
    return True


def _split_media_source_query(value: object) -> tuple[str, ...]:
    """展开重复或逗号分隔的来源参数，并在枚举校验前规范历史别名。"""
    if value in (None, ""):
        return ()
    values = value if isinstance(value, (list, tuple)) else (value,)
    sources = tuple(
        source.strip()
        for item in values
        for source in str(item).split(",")
        if source.strip()
    )
    return tuple(
        normalized.value if (normalized := normalize_media_source(source)) else source
        for source in sources
    )


def _get_source(obj: Union[schemas.MediaInfo, schemas.MediaPerson, dict]):
    """
    获取对象的 source 属性（兼容 dict 与模型对象）。
    """
    if isinstance(obj, dict):
        return obj.get("media_source")
    return obj.media_source


async def search_media(
    title: str,
    type: str = "media",
    page: int = 1,
    count: int = 8,
    media_source: tuple = (),
) -> List[dict]:
    """
    模糊搜索媒体/合集/人物/音乐信息：按 SEARCH_SOURCE 配置排序并分页。

    :param title: 搜索关键词
    :param type: 搜索类型，支持 media、music、collection、person
    :param page: 页码
    :param count: 每页数量
    :param media_source: 请求级搜索数据源枚举，可多选
    :return: 搜索结果列表
    """
    # 直接函数调用也可能绕过 FastAPI/Pydantic，仅在该测试与内部兼容边界补一次规范化。
    selected_sources = (
        media_source
        if isinstance(media_source, tuple)
        and all(isinstance(source, MediaSource) for source in media_source)
        else parse_media_source_selection(",".join(_split_media_source_query(media_source)))
    )
    selected_sources = tuple(dict.fromkeys(selected_sources))
    source_selection = selected_sources or None

    media_chain = MediaChain()
    if type == "music" or any(is_music_media_source(source) for source in selected_sources):
        # 音乐搜索统一入口，与影视搜索共用 /media/search
        music_search_params = {"query": title, "limit": count}
        # 未指定来源时由 MediaChain 使用默认 MusicBrainz 来源。
        if source_selection:
            music_search_params["media_source"] = source_selection
        music_infos = await media_chain.async_search_music(**music_search_params)
        return [
            info.to_dict()
            for info in music_infos
        ] if music_infos else []
    if type == "media":
        _, medias = await media_chain.async_search(
            title=title, media_source=source_selection
        )
        result = [media.to_dict() for media in medias] if medias else []
    elif type == "collection":
        collections = await media_chain.async_search_collections(
            name=title, media_source=source_selection
        )
        result = (
            [collection.to_dict() for collection in collections] if collections else []
        )
    else:  # person
        persons = await media_chain.async_search_persons(
            name=title, media_source=source_selection
        )
        result = [person.model_dump() for person in persons] if persons else []

    if not result:
        return []

    # 排序和分页
    setting_order = settings.SEARCH_SOURCE.split(",") if settings.SEARCH_SOURCE else []
    sort_order = {source: index for index, source in enumerate(setting_order)}

    sorted_result = sorted(result, key=lambda x: sort_order.get(_get_source(x), 4))
    return sorted_result[(page - 1) * count : page * count]

def scrape_path(
    fileitem: schemas.FileItem,
    storage: str = "local",
    media_source: Optional[MediaSource] = None,
    media_id: Optional[str] = None,
    type_name: Optional[MediaType] = None,
    music_type: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    刮削媒体信息：识别媒体 → 本地路径校验 → scrape_metadata。可按请求指定媒体数据源及其原生ID。
    音频文件、音乐数据源与 MUSIC 类型走音乐刮削。

    :param fileitem: 待刮削文件项
    :param storage: 文件所在存储
    :param media_source: 请求级媒体数据源
    :param media_id: 数据源原生ID
    :param type_name: 媒体类型
    :param music_type: 音乐实体类型，支持 recording 和 album
    :return: (success, message)
    """
    if not fileitem or not fileitem.path:
        return False, "刮削路径无效"
    normalized_media_id = media_id.strip() if media_id else None
    if normalized_media_id and not media_source:
        return False, "指定媒体ID时必须同时指定媒体数据源"
    if normalized_media_id and not _is_valid_source_media_id(media_source, normalized_media_id):
        return False, "媒体ID格式无效"

    is_music = (
        type_name == MediaType.MUSIC
        or is_music_media_source(media_source)
        or MediaChain.is_audio_path(fileitem.path)
    )
    if is_music:
        if type_name not in (None, MediaType.MUSIC):
            return False, "音乐元数据源只能用于音乐刮削"
        music_info: Optional[MusicInfo] = None
        if normalized_media_id:
            normalized_music_type = normalize_music_type(
                music_type or MUSIC_ENTITY_RECORDING,
                allow_artist=False,
            )
            if not normalized_music_type:
                return False, "音乐实体类型无效，仅支持 recording 或 album"
            # 音乐与影视共用统一识别入口，按媒体源和原生 ID 恢复音乐详情
            music_info = MediaChain().recognize_media(
                media_source=media_source or MediaSource.MusicBrainz,
                media_id=normalized_media_id,
                mtype=MediaType.MUSIC,
                music_type=normalized_music_type,
            )
            if not music_info:
                return False, "刮削失败，无法识别音乐信息"
        return ScrapingChain().scrape_music_metadata(
            fileitem=fileitem,
            mediainfo=music_info,
            overwrite=True,
            media_source=media_source,
        )

    chain = MediaChain()
    if normalized_media_id:
        meta_info = MetaInfoPath(Path(fileitem.path))
        media_info = chain.recognize_media(
            meta=meta_info,
            mtype=type_name,
            media_source=media_source,
            media_id=normalized_media_id,
        )
        if media_info:
            media_info.scrape_source = media_source
            chain.obtain_images(mediainfo=media_info)
    else:
        context = chain.recognize_by_path(
            fileitem.path,
            media_source=media_source,
            obtain_images=True,
        )
        meta_info = context.meta_info if context else None
        media_info = context.media_info if context else None

    if not media_info:
        return False, "刮削失败，无法识别媒体信息"
    if media_source:
        media_info.scrape_source = media_source
    if storage == "local":
        if not Path(fileitem.path).exists():
            return False, "刮削路径不存在"
    # 手动刮削 (暂时使用同步版本，可以后续优化为异步)
    ScrapingChain().scrape_metadata(
        fileitem=fileitem,
        meta=meta_info,
        mediainfo=media_info,
        overwrite=True,
    )
    return True, f"{fileitem.path} 刮削完成"
