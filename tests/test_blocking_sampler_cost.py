"""阻塞采样的单次开销契约。

采样器以 10Hz 常驻运行，归因只需要文件名、行号与函数名。`traceback.extract_stack`
会为栈中每个文件调用 `linecache.checkcache` 触发 `os.stat` 并读取源码行，在该频率下
这笔开销会成为可观的常驻负担，还会反过来加剧它本该测量的事件循环延迟。
"""

from __future__ import annotations

import linecache
import sys

from app.runtime.diagnostics import blocking


def test_frame_attribution_does_not_touch_linecache(monkeypatch):
    """帧归因不得触发 linecache 校验，避免每次采样按栈深产生 stat 调用。"""
    calls = []
    monkeypatch.setattr(
        linecache, "checkcache", lambda *args, **kwargs: calls.append(args)
    )

    blocking.attribute_plugin_from_frame(sys._getframe())

    assert calls == []


def test_frame_attribution_finds_innermost_plugin_frame():
    """归因返回最贴近阻塞点的插件帧，取文件名、行号与函数名。"""
    source = (
        "def outer(hook):\n"
        "    return inner(hook)\n"
        "def inner(hook):\n"
        "    return hook()\n"
    )
    namespace: dict = {}
    code = compile(source, "/app/plugins/demoplugin/__init__.py", "exec")
    exec(code, namespace)  # noqa: S102

    captured = {}

    def hook():
        captured["attribution"] = blocking.attribute_plugin_from_frame(sys._getframe())

    namespace["outer"](hook)

    attribution = captured["attribution"]
    assert attribution is not None
    assert attribution.plugin_id == "demoplugin"
    assert attribution.file == "/app/plugins/demoplugin/__init__.py"
    assert attribution.function == "inner"


def test_frame_attribution_returns_none_without_plugin_frames():
    """栈中没有插件代码时返回 None。"""
    assert blocking.attribute_plugin_from_frame(sys._getframe()) is None


def test_frame_attribution_handles_missing_frame():
    """取不到帧时返回 None。"""
    assert blocking.attribute_plugin_from_frame(None) is None
