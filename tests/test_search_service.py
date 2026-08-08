"""
S7b 抽取验证：app.service.search 纯解析/格式化逻辑单测。

这些函数原本埋在 919 行的 app/api/endpoints/search.py 中；抽出后不依赖 Chain，
可在本地 venv 直接单测。
"""
import json

from app.schemas.types import MediaType
from app.service import search


def test_parse_site_list_basic():
    assert search.parse_site_list("1,2,3") == [1, 2, 3]


def test_parse_site_list_filters_empty_segments():
    # 末尾/中间空段应被过滤
    assert search.parse_site_list("1,,2,") == [1, 2]


def test_parse_site_list_none_and_empty():
    assert search.parse_site_list(None) is None
    assert search.parse_site_list("") is None


def test_parse_media_type_frontend_and_agent_values():
    assert search.parse_media_type("movie") == MediaType.MOVIE
    assert search.parse_media_type("tv") == MediaType.TV
    assert search.parse_media_type("电影") == MediaType.MOVIE
    assert search.parse_media_type("电视剧") == MediaType.TV


def test_parse_media_type_none():
    assert search.parse_media_type(None) is None
    assert search.parse_media_type("") is None


def test_sse_event_format_and_unicode():
    out = search.sse_event({"type": "ping", "msg": "中文"})
    assert out.startswith("data: ")
    assert out.endswith("\n\n")
    # ensure_ascii=False：中文不转义
    assert "中文" in out
    # 负载是合法 JSON
    payload = json.loads(out[len("data: "):].strip())
    assert payload == {"type": "ping", "msg": "中文"}


def test_merge_append_event_no_pending():
    event = {"type": "append", "items": [1, 2]}
    merged = search.merge_append_event(None, event)
    assert merged["items"] == [1, 2]
    # 返回的是副本，不污染入参
    assert merged is not event


def test_merge_append_event_missing_items_defaults_empty():
    merged = search.merge_append_event(None, {"type": "append"})
    assert merged["items"] == []


def test_merge_append_event_concatenates_and_marks_append():
    pending = {"type": "append", "items": [1, 2], "keyword": "a"}
    event = {"type": "result", "items": [3], "keyword": "b"}
    merged = search.merge_append_event(pending, event)
    # items 拼接
    assert merged["items"] == [1, 2, 3]
    # 非 items 字段以新事件为准
    assert merged["keyword"] == "b"
    # 合并结果统一标记为 append
    assert merged["type"] == "append"
    # 不污染原 pending
    assert pending["items"] == [1, 2]
