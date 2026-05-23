from typing import List, Optional

from app.core.config import settings
from app.log import logger

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


def is_config_enabled() -> bool:
    """
    判断系统配置是否允许使用 Rust 加速。
    """
    return bool(settings.RUST_ACCEL, True)


def is_enabled() -> bool:
    """
    判断当前运行时是否实际启用 Rust 加速。
    """
    return is_config_enabled() and is_available()


def status() -> dict:
    """
    返回 Rust 加速能力与开关状态，供系统配置接口展示。
    """
    return {
        "available": is_available(),
        "enabled": is_enabled(),
        "import_error": str(_import_error) if _import_error else "",
    }


def import_error() -> Optional[Exception]:
    """
    返回 Rust 扩展导入失败的异常，便于调试构建问题。
    """
    return _import_error


def parse_filter_rule(expression: str) -> Optional[list]:
    """
    使用 Rust 解析过滤规则表达式，不可用时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.parse_filter_rule_fast(expression)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 过滤规则解析失败，回退 Python：{err}")
        return None


def filter_torrents(
        groups: list,
        torrent_list: list,
        rule_set: dict,
        mediainfo=None,
        metainfo_options: Optional[dict] = None,
) -> Optional[list]:
    """
    使用 Rust 执行完整种子过滤入口，返回原列表下标和优先级。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.filter_torrents_fast(
            groups,
            torrent_list,
            rule_set,
            mediainfo,
            metainfo_options or {},
        )
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 种子过滤失败，回退 Python：{err}")
        return None

def parse_indexer_torrents(
        html_text: str,
        domain: str,
        list_config: dict,
        fields: dict,
        category: Optional[dict] = None,
        result_num: int = 100
) -> Optional[List[dict]]:
    """
    使用 Rust 批量解析普通配置站点种子列表，不可用时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.parse_indexer_torrents_fast(
            html_text,
            domain,
            list_config,
            fields,
            category,
            result_num
        )
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 站点列表解析失败，使用 Python 解析兜底：{err}")
        return None


def parse_rss_items(xml_text: str, max_items: int = 1000) -> Optional[List[dict]]:
    """
    使用 Rust 解析 RSS/Atom 条目，不可用或异常时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.parse_rss_items_fast(xml_text, max_items)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust RSS解析失败，使用 Python 解析兜底：{err}")
        return None


def parse_metainfo(title: str, subtitle: Optional[str] = None, options: Optional[dict] = None) -> Optional[dict]:
    """
    使用 Rust 从标题入口解析 MetaInfo，不可用或异常时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.parse_metainfo_fast(title, subtitle, options or {})
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust MetaInfo解析失败，使用 Python 解析兜底：{err}")
        return None


def parse_metainfo_path(path: str, options: Optional[dict] = None) -> Optional[dict]:
    """
    使用 Rust 从路径入口解析 MetaInfoPath，不可用或异常时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.parse_metainfo_path_fast(path, options or {})
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust MetaInfoPath解析失败，使用 Python 解析兜底：{err}")
        return None


def find_metainfo(title: str) -> Optional[dict]:
    """
    使用 Rust 提取标题中的显式媒体标签，不可用或异常时返回 None。
    """
    if not is_enabled():
        return None
    try:
        return _moviepilot_rust.find_metainfo_fast(title)
    except BaseException as err:
        _raise_non_rust_panic(err)
        logger.debug(f"Rust 显式媒体标签解析失败，使用 Python 解析兜底：{err}")
        return None


def _raise_non_rust_panic(err: BaseException) -> None:
    """
    只吞掉 Rust 扩展 panic/异常，保留用户中断和进程退出语义。
    """
    if isinstance(err, (KeyboardInterrupt, SystemExit)):
        raise err
