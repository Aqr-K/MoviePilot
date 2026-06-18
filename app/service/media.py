"""
媒体端点的 Chain 编排（service layer）。

模糊搜索（MediaChain 按 media/collection/person 分支检索 + 按 SEARCH_SOURCE 排序 +
分页）与刮削（MediaChain 识别 + 本地路径校验 + scrape_metadata）。从端点下沉到服务层：
端点退化为薄 HTTP 适配层；本层可通过 mock MediaChain 单测。
"""
from pathlib import Path
from typing import List, Tuple, Union

from app import schemas
from app.chain.media import MediaChain
from app.core.config import settings


def _get_source(obj: Union[schemas.MediaInfo, schemas.MediaPerson, dict]):
    """
    获取对象的 source 属性（兼容 dict 与模型对象）。
    """
    if isinstance(obj, dict):
        return obj.get("source")
    return obj.source


async def search_media(
    title: str,
    type: str = "media",
    page: int = 1,
    count: int = 8,
) -> List[dict]:
    """
    模糊搜索媒体/合集/人物信息：按 SEARCH_SOURCE 配置排序并分页。
    media：媒体信息，collection：合集，person：人物信息。
    """
    media_chain = MediaChain()
    if type == "media":
        _, medias = await media_chain.async_search(title=title)
        result = [media.to_dict() for media in medias] if medias else []
    elif type == "collection":
        collections = await media_chain.async_search_collections(name=title)
        result = (
            [collection.to_dict() for collection in collections] if collections else []
        )
    else:  # person
        persons = await media_chain.async_search_persons(name=title)
        result = [person.model_dump() for person in persons] if persons else []

    if not result:
        return []

    # 排序和分页
    setting_order = settings.SEARCH_SOURCE.split(",") if settings.SEARCH_SOURCE else []
    sort_order = {source: index for index, source in enumerate(setting_order)}

    sorted_result = sorted(result, key=lambda x: sort_order.get(_get_source(x), 4))
    return sorted_result[(page - 1) * count : page * count]


def scrape_path(fileitem: schemas.FileItem, storage: str = "local") -> Tuple[bool, str]:
    """
    刮削媒体信息：识别媒体 → 本地路径校验 → scrape_metadata。返回 (success, message)。
    """
    if not fileitem or not fileitem.path:
        return False, "刮削路径无效"
    chain = MediaChain()
    # 识别媒体信息
    context = chain.recognize_by_path(fileitem.path, obtain_images=True)
    if not context or not context.media_info:
        return False, "刮削失败，无法识别媒体信息"
    if storage == "local":
        if not Path(fileitem.path).exists():
            return False, "刮削路径不存在"
    # 手动刮削 (暂时使用同步版本，可以后续优化为异步)
    chain.scrape_metadata(
        fileitem=fileitem,
        meta=context.meta_info,
        mediainfo=context.media_info,
        overwrite=True,
    )
    return True, f"{fileitem.path} 刮削完成"
