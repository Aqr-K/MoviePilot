"""
搜索端点的纯协议/解析逻辑（service layer）。

均为无副作用的纯函数：站点列表解析、媒体类型解析、SSE 事件格式化、
append 事件合并。不依赖 Chain/DB，可独立单测。
端点 app/api/endpoints/search.py 负责鉴权、Chain 调用与 SSE 流编排。
"""
import json
from typing import Any, AsyncIterator, List, Optional

from app.helper.locale import LocaleHelper
from app.schemas.types import MediaType
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
