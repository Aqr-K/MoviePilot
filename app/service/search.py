"""
搜索端点的纯协议/解析逻辑（service layer）。

均为无副作用的纯函数：站点列表解析、媒体类型解析、SSE 事件格式化、
append 事件合并。不依赖 Chain/DB，可独立单测。
端点 app/api/endpoints/search.py 负责鉴权、Chain 调用与 SSE 流编排。
"""
import json
from typing import Any, AsyncIterator, List, Optional, Tuple

from app.chain.media import MediaChain
from app.core.config import settings
from app.core.event import eventmanager
from app.core.metainfo import MetaInfo
from app.helper.locale import LocaleHelper
from app.schemas import MediaRecognizeConvertEventData
from app.schemas.types import ChainEventType, MediaType
from app.utils.media import parse_media_key, resolve_media_identity
from app.utils.security import SecurityUtils


def parse_site_list(sites: Optional[str]) -> Optional[List[int]]:
    """
    解析站点ID列表
    """
    return [int(site) for site in sites.split(",") if site] if sites else None


def parse_media_type(mtype: Optional[str]) -> Optional[MediaType]:
    """
    解析媒体类型，兼容前端和 Agent 使用的 movie/tv 取值。
    """
    if not mtype:
        return None
    return MediaType.from_agent(mtype) or MediaType(mtype)


def resolve_media_season(
        explicit_season: Optional[int],
        recognized_season: Optional[int],
) -> Optional[int]:
    """
    合并显式季号与识别结果，显式值优先且季 0 属于有效业务值。
    """
    return explicit_season if explicit_season is not None else recognized_season


async def resolve_media_search_params(
        mediaid: str,
        media_type: Optional[MediaType] = None,
        title: Optional[str] = None,
        year: Optional[str] = None,
        media_season: Optional[int] = None,
) -> Tuple[Optional[dict], str]:
    """
    将任意来源媒体键解析为 SearchChain 可直接使用的识别参数。

    :param mediaid: 带来源前缀的媒体键
    :param media_type: 媒体类型
    :param title: 名称兜底识别用标题
    :param year: 名称兜底识别用年份
    :param media_season: 名称兜底识别用季号
    :return: (识别参数, 错误信息)；识别参数为 None 时错误信息非空
    """
    source, source_media_id = parse_media_key(mediaid)
    if source and source_media_id:
        if source in {"themoviedb", "bangumi", "anilist"} \
                and not source_media_id.isdigit():
            return None, "媒体ID格式错误"
        return {"source": source, "mediaid": source_media_id}, ""

    event_data = MediaRecognizeConvertEventData(
        mediaid=mediaid, convert_type=settings.RECOGNIZE_SOURCE
    )
    event = await eventmanager.async_send_event(
        ChainEventType.MediaRecognizeConvert, event_data
    )
    if event and event.event_data and event.event_data.media_dict:
        event_data = event.event_data
        search_id = event_data.media_dict.get("id")
        if search_id is not None:
            return {
                "source": event_data.convert_type,
                "mediaid": str(search_id),
            }, ""

    if not title:
        return None, "未知的媒体ID"

    meta = MetaInfo(title)
    if year:
        meta.year = year
    if media_type:
        meta.type = media_type
    if media_season is not None:
        meta.type = MediaType.TV
        meta.begin_season = media_season
    mediainfo = await MediaChain().async_recognize_by_meta(
        meta,
        obtain_images=False,
    )
    if not mediainfo:
        return None, "未识别到媒体信息"
    source, source_media_id = resolve_media_identity(media=mediainfo)
    if not source or not source_media_id:
        return None, "媒体信息缺少有效ID"
    return {"source": source, "mediaid": source_media_id}, ""


def sse_event(data: dict, locale: Optional[str] = None) -> str:
    """
    转换为SSE事件
    """
    payload = data
    message = payload.get("message")
    text = payload.get("text")
    if isinstance(message, str) or isinstance(text, str):
        payload = data.copy()
        if isinstance(message, str):
            payload["message_i18n"] = LocaleHelper.translate_text(
                message, locale=locale
            )
        if isinstance(text, str):
            payload["text_i18n"] = LocaleHelper.translate_text(text, locale=locale)
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def merge_append_event(pending_event: Optional[dict], event: dict) -> dict:
    """
    合并短时间内连续到达的 append 事件，降低前端刷新频率。
    """
    items = list(event.get("items") or [])
    if not pending_event:
        merged_event = dict(event)
        merged_event["items"] = items
        return merged_event

    merged_event = dict(pending_event)
    merged_event.update({key: value for key, value in event.items() if key != "items"})
    merged_event["type"] = "append"
    merged_event["items"] = [*(pending_event.get("items") or []), *items]
    return merged_event


def serialize_signed_subtitle_result(subtitle: Any) -> dict:
    """
    序列化字幕结果并签名下载链接，签名用途绑定站点 ID。
    """
    data = subtitle.to_dict() if hasattr(subtitle, "to_dict") else dict(subtitle)
    enclosure = data.get("enclosure")
    if enclosure:
        data["enclosure"] = SecurityUtils.sign_url(
            enclosure,
            purpose=SecurityUtils.subtitle_download_purpose(data.get("site")),
        )
    return data


def serialize_signed_subtitle_results(subtitles: List[Any]) -> List[dict]:
    """
    批量序列化字幕结果，确保返回给客户端的下载链接均已签名。
    """
    return [serialize_signed_subtitle_result(subtitle) for subtitle in subtitles]


def sign_subtitle_search_event(event: dict) -> dict:
    """
    签名字幕搜索流事件中的下载链接。
    """
    signed_event = dict(event)
    if "items" in signed_event:
        signed_event["items"] = serialize_signed_subtitle_results(
            signed_event.get("items") or []
        )
    return signed_event


async def iter_signed_subtitle_search_events(
    event_source: AsyncIterator[dict],
) -> AsyncIterator[dict]:
    """
    输出仅包含签名字幕下载链接的搜索流事件。
    """
    async for event in event_source:
        yield sign_subtitle_search_event(event)
