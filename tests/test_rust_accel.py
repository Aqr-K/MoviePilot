import pytest

from app.utils import rust_accel


pytestmark = pytest.mark.skipif(
    not rust_accel.is_available(),
    reason="moviepilot_rust 扩展未安装",
)


def test_rust_filter_rule_parser_matches_boolean_semantics():
    """
    Rust 过滤规则解析应保持 pyparsing 的布尔表达式结构。
    """
    result = rust_accel.parse_filter_rule("HDR & !BLU")

    assert result == [["HDR", "and", ["not", "BLU"]]]


def test_rust_filter_rule_parser_handles_parentheses_and_or():
    """
    Rust 过滤规则解析应保持括号、与、或的优先级语义。
    """
    result = rust_accel.parse_filter_rule("CNSUB & (4K | 1080P) & !BLU")

    assert result == [[["CNSUB", "and", ["4K", "or", "1080P"]], "and", ["not", "BLU"]]]
