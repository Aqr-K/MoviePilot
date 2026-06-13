import warnings

import app


def test_app_installs_known_oss2_invalid_escape_warning_filter():
    """
    app 初始化过滤器应覆盖 oss2 在 Python 3.12 下产生的无害转义警告。
    """
    app._filter_third_party_startup_warnings()
    action, message, category, module, lineno = warnings.filters[0]

    assert action == "ignore"
    assert message.match("invalid escape sequence '\\&'")
    assert category is SyntaxWarning
    assert module is None
    assert lineno == 0
