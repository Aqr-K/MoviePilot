from typing import List, Any, Annotated, Optional

from fastapi import APIRouter, Depends

from app import schemas
from app.chain.media import MediaChain
from app.chain.tmdb import TmdbChain
from app.core.config import settings
from app.core.context import Context
from app.core.event import eventmanager
from app.core.metainfo import MetaInfo
from app.core.security import verify_token, verify_apitoken
from app.db.models import User
from app.db.user_oper import get_current_active_user, get_current_active_superuser
from app.schemas import MediaType, MediaRecognizeConvertEventData
from app.schemas.category import CategoryConfig
from app.schemas.types import ChainEventType
from app.service.media import (
    scrape_path as _scrape_path,
    search_media as _search_media,
)
from app.utils.media import parse_media_key

router = APIRouter()
MediaSource = str


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
            poster_path=item.get("poster_path"),
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
    source: Optional[MediaSource] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据标题、副标题识别媒体信息
    :param title: 标题
    :param subtitle: 副标题
    :param custom_words: 临时识别词（每行一条规则），传入时仅在本次识别中生效，不会保存到系统配置
    :param source: 请求级识别数据源
    :param _:
    """
    # 识别媒体信息，传入临时识别词时优先于系统配置的识别词生效
    metainfo = MetaInfo(
        title, subtitle, custom_words=custom_words.split("\n") if custom_words else None
    )
    mediainfo = await MediaChain().async_recognize_by_meta(
        metainfo,
        source=source,
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
    source: Optional[MediaSource] = None,
) -> Any:
    """
    根据标题、副标题识别媒体信息 API_TOKEN认证（?token=xxx）
    """
    # 识别媒体信息
    return await recognize(title, subtitle, custom_words, source)


@router.get(
    "/recognize_file", summary="识别媒体信息（文件）", response_model=schemas.Context
)
async def recognize_file(
    path: str,
    source: Optional[MediaSource] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据文件路径识别媒体信息
    """
    # 识别媒体信息
    context = await MediaChain().async_recognize_by_path(path, source=source)
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
    source: Optional[MediaSource] = None,
) -> Any:
    """
    根据文件路径识别媒体信息 API_TOKEN认证（?token=xxx）
    """
    # 识别媒体信息
    return await recognize_file(path, source)


@router.get("/search", summary="搜索媒体/人物信息", response_model=List[dict])
async def search(
    title: str,
    type: Optional[str] = "media",
    page: int = 1,
    count: int = 8,
    source: Optional[MediaSource] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    模糊搜索媒体、合集或人物信息列表。

    :param title: 搜索关键词
    :param type: 搜索类型，支持 media、collection、person
    :param page: 页码
    :param count: 每页数量
    :param source: 请求级搜索数据源
    :param _: Token校验
    :return: 搜索结果列表
    """
    return await _search_media(title=title, type=type, page=page, count=count, source=source)


@router.post(
    "/scrape/{storage}", summary="刮削媒体信息", response_model=schemas.Response
)
def scrape(
    fileitem: schemas.FileItem,
    storage: Optional[str] = "local",
    media_source: Optional[MediaSource] = None,
    media_id: Optional[str] = None,
    type_name: Optional[MediaType] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    刮削媒体信息，可按请求指定媒体数据源及其原生ID

    :param fileitem: 待刮削文件项
    :param storage: 文件所在存储
    :param media_source: 请求级媒体数据源
    :param media_id: 数据源原生ID
    :param type_name: 媒体类型
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
    "/category/config", summary="获取分类策略配置", response_model=schemas.Response
)
def get_category_config(_: User = Depends(get_current_active_user)):
    """
    获取分类策略配置
    """
    config = MediaChain().category_config()
    return schemas.Response(success=True, data=config.model_dump())


@router.post(
    "/category/config", summary="保存分类策略配置", response_model=schemas.Response
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


@router.get("/category", summary="查询自动分类配置", response_model=dict)
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
    return await TmdbChain().async_tmdb_group_seasons(group_id=episode_group)


@router.get("/groups/{tmdbid}", summary="查询媒体剧集组", response_model=List[dict])
async def groups(tmdbid: int, _: schemas.TokenPayload = Depends(verify_token)) -> Any:
    """
    查询媒体剧集组列表（themoviedb）
    """
    mediainfo = await MediaChain().async_recognize_media(
        tmdbid=tmdbid, mtype=MediaType.TV
    )
    if not mediainfo:
        return []
    return mediainfo.episode_groups


@router.get(
    "/seasons", summary="查询媒体季信息", response_model=List[schemas.MediaSeason]
)
async def seasons(
    mediaid: Optional[str] = None,
    title: Optional[str] = None,
    year: str = None,
    season: int = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    查询媒体季信息
    """
    if mediaid:
        media_source, source_media_id = parse_media_key(mediaid)
        if media_source == "themoviedb":
            tmdbid = int(source_media_id)
            seasons_info = await TmdbChain().async_tmdb_seasons(tmdbid=tmdbid)
            if seasons_info:
                if season is not None:
                    return [sea for sea in seasons_info if sea.season_number == season]
                return seasons_info
        elif media_source and source_media_id:
            mediainfo = await MediaChain().async_recognize_media(
                source=media_source,
                mediaid=source_media_id,
                mtype=MediaType.TV,
                cache=False,
            )
            if mediainfo:
                return _build_media_seasons(mediainfo, season)
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
            if mediainfo.source == "themoviedb" and mediainfo.tmdb_id:
                seasons_info = await TmdbChain().async_tmdb_seasons(
                    tmdbid=mediainfo.tmdb_id
                )
                if seasons_info:
                    if season is not None:
                        return [
                            sea for sea in seasons_info if sea.season_number == season
                        ]
                    return seasons_info
            return _build_media_seasons(mediainfo, season)
    return []


@router.get("/{mediaid}", summary="查询媒体详情", response_model=schemas.MediaInfo)
async def detail(
    mediaid: str,
    type_name: str,
    title: Optional[str] = None,
    year: str = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    根据带来源前缀的媒体ID查询媒体信息，type_name: 电影/电视剧
    """
    mtype = MediaType(type_name)
    mediainfo = None
    mediachain = MediaChain()
    media_source, source_media_id = parse_media_key(mediaid)
    if media_source and source_media_id:
        mediainfo = await mediachain.async_recognize_media(
            source=media_source,
            mediaid=source_media_id,
            mtype=mtype,
        )
    else:
        # 广播事件解析媒体信息
        event_data = MediaRecognizeConvertEventData(
            mediaid=mediaid, convert_type=settings.RECOGNIZE_SOURCE
        )
        event = await eventmanager.async_send_event(
            ChainEventType.MediaRecognizeConvert, event_data
        )
        # 使用事件返回的上下文数据
        if event and event.event_data and event.event_data.media_dict:
            event_data: MediaRecognizeConvertEventData = event.event_data
            new_id = event_data.media_dict.get("id")
            if new_id is not None and event_data.convert_type:
                mediainfo = await mediachain.async_recognize_media(
                    source=event_data.convert_type,
                    mediaid=str(new_id),
                    mtype=mtype,
                )
        elif title:
            # 使用名称识别兜底
            meta = MetaInfo(title)
            if year:
                meta.year = year
            if mtype:
                meta.type = mtype
            mediainfo = await mediachain.async_recognize_by_meta(
                meta,
                obtain_images=False,
            )
    # 识别
    if mediainfo:
        await mediachain.async_obtain_images(mediainfo)
        return mediainfo.to_dict()

    return schemas.MediaInfo()
