from typing import Any, Dict, List, Optional, Tuple

from app.log import logger
from app.schemas.types import MediaType

try:
    import moviepilot_rust as _moviepilot_rust
except Exception as err:  # pragma: no cover - 取决于运行环境是否安装 Rust 扩展
    _moviepilot_rust = None
    _import_error = err
else:
    _import_error = None


def is_available() -> bool:
    """
    判断 Rust 扩展是否可用。
    """
    return bool(_moviepilot_rust and _moviepilot_rust.is_available())


def import_error() -> Optional[Exception]:
    """
    返回 Rust 扩展导入失败的异常，便于调试构建问题。
    """
    return _import_error


def is_anime(name: str) -> Optional[bool]:
    """
    使用 Rust 快路径判断标题是否为动漫格式，不可用时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return bool(_moviepilot_rust.is_anime_fast(name or ""))
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 动漫识别失败，回退 Python：{err}")
        return None


def find_metainfo(title: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    使用 Rust 快路径提取标题中的内嵌媒体标签，不可用时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        result = _moviepilot_rust.find_metainfo_fast(title or "")
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 内嵌媒体标签识别失败，回退 Python：{err}")
        return None
    metainfo = {
        "tmdbid": result.get("tmdbid"),
        "doubanid": result.get("doubanid"),
        "type": _coerce_media_type(result.get("type")),
        "begin_season": result.get("begin_season"),
        "end_season": result.get("end_season"),
        "total_season": result.get("total_season"),
        "begin_episode": result.get("begin_episode"),
        "end_episode": result.get("end_episode"),
        "total_episode": result.get("total_episode"),
    }
    return result.get("title"), metainfo


def parse_video_title(
        title: str,
        isfile: bool = False,
        media_exts: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    使用 Rust 执行影视标题主识别流程，不可用时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.parse_video_title_fast(title or "", isfile, media_exts or [])
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 影视标题主识别失败，回退 Python：{err}")
        return None


def parse_filter_rule(expression: str) -> Optional[list]:
    """
    使用 Rust 解析过滤规则表达式，不可用时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.parse_filter_rule_fast(expression)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 过滤规则解析失败，回退 Python：{err}")
        return None


def filter_torrents(
        rule_set: Dict[str, dict],
        rule_strings: List[str],
        torrents: List[dict],
        media_info: Optional[dict] = None,
) -> Optional[list]:
    """
    使用 Rust 批量执行种子过滤，不可用或不兼容时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.filter_torrents_fast(rule_set, rule_strings, torrents, media_info)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 种子过滤失败，回退 Python：{err}")
        return None


def build_indexer_search_url(config: dict) -> Optional[str]:
    """
    使用 Rust 根据普通 indexer 配置生成搜索 URL，不可用时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.build_indexer_search_url_fast(config)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 站点搜索 URL 生成失败，回退 Python：{err}")
        return None


def parse_indexer_torrents(
        html_text: str,
        domain: str,
        list_config: dict,
        fields: dict,
        category: Optional[dict],
        result_num: int,
) -> Optional[List[dict]]:
    """
    使用 Rust 批量解析普通 indexer 页面，不支持的配置返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.parse_indexer_torrents_fast(
            html_text or "",
            domain or "",
            list_config or {},
            fields or {},
            category,
            int(result_num or 0),
        )
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 站点页面解析失败，回退 Python：{err}")
        return None


def parse_rss_items(xml_text: str, max_items: int) -> Optional[List[dict]]:
    """
    使用 Rust 批量解析 RSS/Atom 条目，不可用或解析失败时返回 None。
    """
    if not _moviepilot_rust:
        return None
    try:
        return _moviepilot_rust.parse_rss_items_fast(xml_text or "", int(max_items or 0))
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust RSS 条目解析失败，回退 Python：{err}")
        return None


def _coerce_media_type(value: Optional[str]) -> Optional[MediaType]:
    """
    将 Rust 返回的媒体类型字符串转换为系统 MediaType。
    """
    if value == "movies":
        return MediaType.MOVIE
    if value == "tv":
        return MediaType.TV
    return None


def _raise_non_rust_panic(err: BaseException) -> None:
    """
    只吞掉 Rust 扩展 panic/异常，保留用户中断和进程退出语义。
    """
    if isinstance(err, (KeyboardInterrupt, SystemExit)):
        raise err
