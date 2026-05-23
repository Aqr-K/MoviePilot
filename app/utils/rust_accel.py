from typing import List, Optional

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


def import_error() -> Optional[Exception]:
    """
    返回 Rust 扩展导入失败的异常，便于调试构建问题。
    """
    return _import_error


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
    if not _moviepilot_rust:
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


def _raise_non_rust_panic(err: BaseException) -> None:
    """
    只吞掉 Rust 扩展 panic/异常，保留用户中断和进程退出语义。
    """
    if isinstance(err, (KeyboardInterrupt, SystemExit)):
        raise err
