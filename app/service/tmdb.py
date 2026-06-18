"""
TMDB 端点的 Chain 编排（service layer）。

类似/推荐/演员阵容均按 type_name（电影/电视剧）分发到 TmdbChain 的不同方法，
再做 to_dict 映射。从端点下沉到服务层，去重分发逻辑并便于 mock TmdbChain 单测。
"""
from typing import Any, List

from app.chain.tmdb import TmdbChain
from app.schemas.types import MediaType


async def similar_medias(tmdbid: int, type_name: str) -> List[dict]:
    """
    类似电影/电视剧（type_name: 电影/电视剧）。
    """
    mediatype = MediaType(type_name)
    if mediatype == MediaType.MOVIE:
        medias = await TmdbChain().async_movie_similar(tmdbid=tmdbid)
    elif mediatype == MediaType.TV:
        medias = await TmdbChain().async_tv_similar(tmdbid=tmdbid)
    else:
        return []
    if medias:
        return [media.to_dict() for media in medias]
    return []


async def recommend_medias(tmdbid: int, type_name: str) -> List[dict]:
    """
    推荐电影/电视剧（type_name: 电影/电视剧）。
    """
    mediatype = MediaType(type_name)
    if mediatype == MediaType.MOVIE:
        medias = await TmdbChain().async_movie_recommend(tmdbid=tmdbid)
    elif mediatype == MediaType.TV:
        medias = await TmdbChain().async_tv_recommend(tmdbid=tmdbid)
    else:
        return []
    if medias:
        return [media.to_dict() for media in medias]
    return []


async def credits_persons(tmdbid: int, type_name: str, page: int = 1) -> List[Any]:
    """
    演员阵容（type_name: 电影/电视剧）。
    """
    mediatype = MediaType(type_name)
    if mediatype == MediaType.MOVIE:
        persons = await TmdbChain().async_movie_credits(tmdbid=tmdbid, page=page)
    elif mediatype == MediaType.TV:
        persons = await TmdbChain().async_tv_credits(tmdbid=tmdbid, page=page)
    else:
        return []
    return persons or []
