# -*- coding: utf-8 -*-
"""
回归测试：init_agent 将初始化协程调度到主事件循环，不再起守护线程 + 临时事件循环。

背景（架构审计 #1）：旧实现每次启动新建守护线程并在其内 ``new_event_loop().run_until_complete``，
Agent 的后台任务（会话 worker / 空闲清理）会绑定在随线程退出即关闭的临时循环上，与关停时
stop_agent 所在的主循环不是同一个，导致关停无法取消这些后台任务。
修复：复用项目既有约定 ``asyncio.run_coroutine_threadsafe(coro, global_vars.loop)``，
使后台任务与关停同处主循环。仅 AI_AGENT_ENABLE=True 时触发调度。
"""
from app.core.config import global_vars
from app.startup import agent_initializer as ai_mod


def test_no_threading_import_left():
    """守护"删守护线程"：模块不应再引入 threading。"""
    assert not hasattr(ai_mod, "threading")


def test_init_agent_schedules_on_main_loop(monkeypatch):
    sentinel_loop = object()
    captured = {}

    def fake_rcts(coro, loop):
        captured["coro"] = coro
        captured["loop"] = loop
        coro.close()  # 仅捕获，不实际运行，关闭以免 "never awaited" 警告
        return object()

    monkeypatch.setattr("asyncio.run_coroutine_threadsafe", fake_rcts)
    monkeypatch.setattr(global_vars, "CURRENT_EVENT_LOOP", sentinel_loop)
    monkeypatch.setattr(ai_mod.settings, "AI_AGENT_ENABLE", True)

    result = ai_mod.init_agent()

    assert result is True
    # 调度发生在 global_vars 主循环上，而非临时新建的循环
    assert captured["loop"] is sentinel_loop
    assert "coro" in captured


def test_init_agent_skips_when_disabled(monkeypatch):
    called = {"scheduled": False}

    def fake_rcts(coro, loop):
        called["scheduled"] = True
        coro.close()
        return object()

    monkeypatch.setattr("asyncio.run_coroutine_threadsafe", fake_rcts)
    monkeypatch.setattr(ai_mod.settings, "AI_AGENT_ENABLE", False)

    result = ai_mod.init_agent()

    assert result is True
    assert called["scheduled"] is False
