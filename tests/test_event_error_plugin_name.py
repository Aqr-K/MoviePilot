# -*- coding: utf-8 -*-
"""
回归测试：插件事件处理抛错时，错误上报使用 plugin.get_name() 而非 plugin.name。

背景（架构审计 #39）：_PluginBase 没有 ``name`` 属性（仅 ``plugin_name`` + ``get_name()``）。
事件管理器旧代码在 except 分支用 ``plugin.name`` 取模块名，会在错误处理器内部二次抛出
AttributeError，把插件真正的业务异常吞掉、且无法发出系统错误通知。
修复：``module_name=plugin.get_name()``（与 _ModuleBase/全局处理器分支一致）。

覆盖同步分支（manager.py 约 :470）与异步分支（约 :547）两处。
"""
import asyncio

import pytest

from app.core.event.manager import EventManager
from app.core.event.models import Event
from app.helper.plugin_manager import PluginManager
from app.plugins import _PluginBase
from app.schemas.types import EventType

_PLUGIN_ID = "_RaisingEventPlugin"
_DISPLAY_NAME = "可读插件名"


class _RaisingEventPlugin:
    """模拟一个 running 插件：仅有 plugin_name/get_name，没有 name 属性，事件方法必抛错。"""

    plugin_name = _DISPLAY_NAME

    def get_name(self) -> str:
        return self.plugin_name

    def do_event(self, event):  # __qualname__ == "_RaisingEventPlugin.do_event"
        raise RuntimeError("插件业务异常")


def test_plugin_base_has_no_name_attribute():
    """守护前提：_PluginBase 提供 get_name 而非 name；否则本修复无意义。"""
    assert hasattr(_PluginBase, "get_name")
    assert not hasattr(_PluginBase, "name")
    plugin = _RaisingEventPlugin()
    assert plugin.get_name() == _DISPLAY_NAME
    assert not hasattr(plugin, "name")


@pytest.fixture
def patched_managers(monkeypatch):
    """把假插件登记进 PluginManager 单例，并捕获 __handle_event_error 的 module_name。"""
    em = EventManager()
    pm = PluginManager()
    plugin = _RaisingEventPlugin()

    monkeypatch.setattr(pm, "get_plugin_ids", lambda: [_PLUGIN_ID])
    monkeypatch.setattr(pm, "_running_plugins", {_PLUGIN_ID: plugin})

    captured = {}

    def _capture(event, module_name, class_name, method_name, e):
        captured["module_name"] = module_name
        captured["error"] = e

    # __handle_event_error 为名称改写的私有方法
    monkeypatch.setattr(em, "_EventManager__handle_event_error", _capture)
    return em, pm, captured


def test_sync_invoke_reports_get_name_without_attribute_error(patched_managers):
    em, _pm, captured = patched_managers
    event = Event(EventType.PluginAction)
    handler = _RaisingEventPlugin.do_event  # __qualname__ -> "_RaisingEventPlugin.do_event"

    # 不应抛出（旧代码会在 except 内因 plugin.name 二次 AttributeError）
    em._EventManager__invoke_handler_by_type_sync(handler, event)

    assert captured["module_name"] == _DISPLAY_NAME
    assert isinstance(captured["error"], RuntimeError)


def test_async_invoke_reports_get_name_without_attribute_error(patched_managers):
    em, pm, captured = patched_managers
    event = Event(EventType.PluginAction)

    asyncio.run(
        em._EventManager__invoke_plugin_method_async(pm, _PLUGIN_ID, "do_event", event)
    )

    assert captured["module_name"] == _DISPLAY_NAME
    assert isinstance(captured["error"], RuntimeError)
