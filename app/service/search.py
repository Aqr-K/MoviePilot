"""
搜索端点的纯协议/解析逻辑（service layer）。

均为无副作用的纯函数：站点列表解析、媒体类型解析、SSE 事件格式化、
append 事件合并。不依赖 Chain/DB，可独立单测。
端点 app/api/endpoints/search.py 负责鉴权、Chain 调用与 SSE 流编排。
"""
import json
from typing import List, Optional

from app.schemas.types import MediaType


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


def sse_event(data: dict) -> str:
    """
    转换为SSE事件
    """
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


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
