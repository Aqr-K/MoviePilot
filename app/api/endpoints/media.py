from pathlib import Path
from typing import List, Any, Annotated, Optional

from fastapi import Depends, Query
from pydantic import BeforeValidator

from app import schemas
from app.api.response import ResponseAPIRouter
from app.chain.media import MediaChain
from app.chain.scraping import ScrapingChain
from app.chain.tmdb import TmdbChain
from app.core.config import settings
from app.core.context import Context, MusicInfo
from app.core.meta import MetaBase, MetaMusic
from app.core.context import Context
from app.core.event import eventmanager
from app.core.meta import MetaBase
from app.core.metainfo import MetaInfo, MetaInfoPath
from app.core.security import verify_token, verify_apitoken
from app.db.models import User
from app.db.user_oper import get_current_active_user, get_current_active_superuser
from app.schemas import MediaType
from app.schemas.category import CategoryConfig
from app.schemas.types import ChainEventType
from app.service.media import (
    scrape_path as _scrape_path,
    search_media as _search_media,
)
from app.utils.media import MEDIA_SOURCE_ID_FIELDS, parse_media_key

router = ResponseAPIRouter()



def _build_recognize_metainfo(
        title: str,
        subtitle: Optional[str] = None,
        custom_words: Optional[str] = None,
) -> MetaBase:
    """构造标题识别元数据，并兼容第三方客户端传入媒体文件路径。"""
    custom_word_list = custom_words.split("\n") if custom_words else None
    normalized_title = title.replace("\\", "/")
    title_path = Path(normalized_title)
    if (
        ("/" in title or "\\" in title)
        and "://" not in title
        and title_path.suffix.lower() in settings.RMT_MEDIAEXT
    ):
        metainfo = MetaInfoPath(
            title_path,
            custom_words=custom_word_list,
        )
        metainfo.title = title
        return metainfo
    return MetaInfo(title, subtitle, custom_words=custom_word_list)


def _build_media_seasons(
        mediainfo: Any, season: Optional[int] = None,
) -> List[schemas.MediaSeason]:
    """将任意数据源的统一媒体信息转换为季信息响应。"""
    seasons_info = []
    for item in mediainfo.season_info or []:
        season_number = item.get("season_number")
        if season is not None and season_number != season:
            continue
        seasons_info.append(schemas.MediaSeason(
            air_date=item.get("air_date"),
            episode_count=item.get("episode_count"),
            name=item.get("name"),
            overview=item.get("overview"),
            poster_path=item.get("poster_path") or mediainfo.poster_path,
            season_number=season_number,
            vote_average=item.get("vote_average"),
        ))
    if seasons_info:
        return seasons_info

    season_numbers = sorted((mediainfo.seasons or {}).keys())
    if season is not None:
        season_numbers = [season]
    elif not season_numbers:
        season_numbers = [mediainfo.season or 1]
    return [
        schemas.MediaSeason(
            season_number=season_number,
            poster_path=mediainfo.poster_path,
            name=f"第 {season_number} 季",
            air_date=mediainfo.release_date,
            overview=mediainfo.overview,
            vote_average=mediainfo.vote_average,
            episode_count=(
                len((mediainfo.seasons or {}).get(season_number) or [])
                or mediainfo.number_of_episodes
            ),
        )
        for season_number in season_numbers
    ]


@router.get(
    "/recognize", summary="识别媒体信息（种子）", response_model=schemas.Context
)
async def recognize(
    title: str,
    subtitle: Optional[str] = None,
    custom_words: Optional[str] = None,
    media_source: Optional[MediaSource] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据标题、副标题识别媒体信息
    :param title: 标题
    :param subtitle: 副标题
    :param custom_words: 临时识别词（每行一条规则），传入时仅在本次识别中生效，不会保存到系统配置
    :param media_source: 请求级识别数据源
    :param _:
    """
    # 识别媒体信息，传入临时识别词时优先于系统配置的识别词生效
    metainfo = _build_recognize_metainfo(title, subtitle, custom_words)
    # 显式音乐来源需要按音乐元数据解析，避免名称测试误入影视识别。
    if is_music_media_source(media_source) and not isinstance(metainfo, MetaMusic):
        metainfo = MetaMusic.parse_query(title)
    mediainfo = await MediaChain().async_recognize_by_meta(
        metainfo,
        media_source=media_source,
    )
    if mediainfo:
        return Context(meta_info=metainfo, media_info=mediainfo).to_dict()
    return schemas.Context()


@router.get(
    "/recognize2",
    summary="识别种子媒体信息（API_TOKEN）",
    response_model=schemas.Context,
)
async def recognize2(
    _: Annotated[str, Depends(verify_apitoken)],
    title: str,
    subtitle: Optional[str] = None,
    custom_words: Optional[str] = None,
    media_source: Optional[MediaSource] = None,
) -> Any:
    """
    根据标题、副标题识别媒体信息 API_TOKEN认证（?token=xxx）
    """
    # 识别媒体信息
    return await recognize(title, subtitle, custom_words, media_source)


@router.get(
    "/recognize_file", summary="识别媒体信息（文件）", response_model=schemas.Context
)
async def recognize_file(
    path: str,
    media_source: Optional[MediaSource] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据文件路径识别媒体信息，影视与音乐统一走媒体链路径识别入口
    """
    # 识别媒体信息
    context = await MediaChain().async_recognize_by_path(
        path, media_source=media_source
    )
    if context:
        return context.to_dict()
    return schemas.Context()


@router.get(
    "/recognize_file2",
    summary="识别文件媒体信息（API_TOKEN）",
    response_model=schemas.Context,
)
async def recognize_file2(
    path: str,
    _: Annotated[str, Depends(verify_apitoken)],
    media_source: Optional[MediaSource] = None,
) -> Any:
    """
    根据文件路径识别媒体信息 API_TOKEN认证（?token=xxx）
    """
    # 识别媒体信息
    return await recognize_file(path, media_source)


@router.get(
    "/search",
    summary="搜索媒体/人物信息",
    response_model=schemas.MediaSearchResults,
)
async def search(
    title: str,
    type: Optional[str] = "media",
    page: int = 1,
    count: int = 8,
    media_source: MediaSourceQuery = (),
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    模糊搜索媒体、合集、人物或音乐信息列表。

    :param title: 搜索关键词
    :param type: 搜索类型，支持 media、music、collection、person
    :param page: 页码
    :param count: 每页数量
    :param media_source: 请求级搜索数据源枚举；可重复传入，逗号格式仅用于兼容旧客户端
    :param _: Token校验
    :return: 搜索结果列表
    """
    return await _search_media(title=title, type=type, page=page, count=count, source=source)


@router.post(
    "/scrape/{storage}", summary="刮削媒体信息", response_model=schemas.Response[None]
)
def scrape(
    fileitem: schemas.FileItem,
    storage: Optional[str] = "local",
    media_source: Optional[MediaSource] = None,
    media_id: Optional[str] = None,
    type_name: Optional[MediaType] = None,
    music_type: Optional[str] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    刮削媒体信息，可按请求指定媒体数据源及其原生ID

    :param fileitem: 待刮削文件项
    :param storage: 文件所在存储
    :param media_source: 请求级媒体数据源
    :param media_id: 数据源原生ID
    :param type_name: 媒体类型
    :param music_type: 音乐实体类型，支持 recording 和 album
    :param _: Token校验
    """
    success, message = _scrape_path(
        fileitem,
        storage,
        media_source=media_source,
        media_id=media_id,
        type_name=type_name,
    )
    return schemas.Response(success=success, message=message)


@router.get(
    "/category/config",
    summary="获取分类策略配置",
    response_model=schemas.Response[schemas.CategoryConfig],
)
def get_category_config(_: User = Depends(get_current_active_user)):
    """
    获取分类策略配置
    """
    config = MediaChain().category_config()
    return schemas.Response(success=True, data=config.model_dump())


@router.post(
    "/category/config", summary="保存分类策略配置", response_model=schemas.Response[None]
)
def save_category_config(
    config: CategoryConfig, _: User = Depends(get_current_active_superuser)
):
    """
    保存分类策略配置
    """
    if MediaChain().save_category_config(config):
        return schemas.Response(success=True, message="保存成功")
    else:
        return schemas.Response(success=False, message="保存失败")


@router.get(
    "/category",
    summary="查询自动分类配置",
    response_model=schemas.MediaCategoryMap,
)
async def category(_: schemas.TokenPayload = Depends(verify_token)) -> Any:
    """
    查询自动分类配置
    """
    return MediaChain().media_category() or {}


@router.get(
    "/group/seasons/{episode_group}",
    summary="查询剧集组季信息",
    response_model=List[schemas.MediaSeason],
)
async def group_seasons(
    episode_group: str, _: schemas.TokenPayload = Depends(verify_token)
) -> Any:
    """
    查询剧集组季信息（themoviedb）
    """
    _, normalized_group_id = resolve_media_identity(
        media_source=MediaSource.TMDB,
        media_id=episode_group,
    )
    if not normalized_group_id:
        return []
    return await TmdbChain().async_tmdb_group_seasons(group_id=normalized_group_id)


@router.get(
    "/groups/{tmdbid}",
    summary="查询媒体剧集组",
    response_model=List[schemas.MediaEpisodeGroup],
)
async def groups(tmdbid: int, _: schemas.TokenPayload = Depends(verify_token)) -> Any:
    """
    查询媒体剧集组列表（themoviedb）
    """
    media_source, media_id = resolve_media_identity(
        media_source=MediaSource.TMDB,
        media_id=tmdbid,
    )
    if not media_source or not media_id:
        return []
    mediainfo = await MediaChain().async_recognize_media(
        media_source=media_source,
        media_id=media_id,
        mtype=MediaType.TV,
    )
    if not mediainfo:
        return []
    return mediainfo.episode_groups


@router.get(
    "/seasons", summary="查询媒体季信息", response_model=List[schemas.MediaSeason]
)
async def seasons(
    media_source: Optional[MediaSource] = None,
    media_id: Optional[str] = None,
    title: Optional[str] = None,
    year: str = None,
    season: int = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    查询媒体季信息
    """
    if media_source is not None or media_id is not None:
        normalized_source, normalized_media_id = resolve_media_identity(
            media_source=media_source,
            media_id=media_id,
        )
        if not normalized_source or not normalized_media_id:
            return []
        if normalized_source == MediaSource.TMDB and normalized_media_id.isdigit():
            tmdbid = int(normalized_media_id)
            seasons_info = await TmdbChain().async_tmdb_seasons(tmdbid=tmdbid)
            if seasons_info:
                if season is not None:
                    return [sea for sea in seasons_info if sea.season_number == season]
                return seasons_info
        else:
            mediainfo = await MediaChain().async_recognize_media(
                media_source=normalized_source,
                media_id=normalized_media_id,
                mtype=MediaType.TV,
                cache=False,
            )
            if mediainfo:
                return _build_media_seasons(mediainfo, season)
        # 明确来源的查询不能按标题切换到默认识别源，避免辅助 TMDB 信息替换主身份。
        return []
    if title:
        meta = MetaInfo(title)
        if year:
            meta.year = year
        meta.type = MediaType.TV
        mediainfo = await MediaChain().async_recognize_by_meta(
            meta,
            obtain_images=False,
        )
        if mediainfo:
            recognized_source, recognized_media_id = resolve_media_identity(
                media=mediainfo
            )
            if (
                recognized_source == MediaSource.TMDB
                and recognized_media_id
                and recognized_media_id.isdigit()
            ):
                seasons_info = await TmdbChain().async_tmdb_seasons(
                    tmdbid=int(recognized_media_id)
                )
                if seasons_info:
                    if season is not None:
                        return [
                            sea for sea in seasons_info if sea.season_number == season
                        ]
                    return seasons_info
            return _build_media_seasons(mediainfo, season)
    return []


@router.get("/{media_id}", summary="查询媒体详情", response_model=schemas.MediaInfo)
async def detail(
    media_id: str,
    media_source: MediaSource,
    type_name: str,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据媒体来源和原生 ID 查询媒体信息，type_name: 电影/电视剧
    """
    mtype = MediaType(type_name)
    normalized_source, normalized_media_id = resolve_media_identity(
        media_source=media_source,
        media_id=media_id,
    )
    if not normalized_source or not normalized_media_id:
        return schemas.MediaInfo()
    mediachain = MediaChain()
    mediainfo = await mediachain.async_recognize_media(
        media_source=normalized_source,
        media_id=normalized_media_id,
        mtype=mtype,
    )
    # 识别
    if mediainfo:
        await mediachain.async_obtain_images(mediainfo)
        # 电视剧且有 TVDB ID 时，补充获取 slug 用于构建 TheTvDb 直达链接
        if mediainfo.type == MediaType.TV and mediainfo.tvdb_id and not mediainfo.tvdb_slug:
            slug = mediachain.tvdb_slug(mediainfo.tvdb_id)
            if slug:
                mediainfo.tvdb_slug = slug
        return mediainfo.to_dict()

    return schemas.MediaInfo()
