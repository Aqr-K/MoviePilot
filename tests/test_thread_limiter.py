"""anyio 默认线程槽容量与共享线程池配置对齐的契约测试。"""

import asyncio
from types import SimpleNamespace

import anyio.to_thread
from fastapi import FastAPI

from app.runtime import thread as thread_module
from app.runtime.config import settings
from app.startup import lifecycle


def test_resolve_default_thread_limit_follows_conf_threadpool_by_default(monkeypatch):
    """未显式覆盖时，线程槽上限跟随共享线程池容量。"""
    monkeypatch.setattr(settings, "API_THREAD_LIMIT", 0)
    monkeypatch.setattr(
        type(settings), "CONF", property(lambda self: SimpleNamespace(threadpool=57))
    )

    assert thread_module.resolve_default_thread_limit() == 57


def test_resolve_default_thread_limit_uses_explicit_override(monkeypatch):
    """显式覆盖时，线程槽上限取配置值，不再跟随共享线程池容量。"""
    monkeypatch.setattr(settings, "API_THREAD_LIMIT", 200)
    monkeypatch.setattr(
        type(settings), "CONF", property(lambda self: SimpleNamespace(threadpool=57))
    )

    assert thread_module.resolve_default_thread_limit() == 200


def test_configure_default_thread_limiter_grows_but_never_shrinks(monkeypatch):
    """线程槽只能调大：目标值更大时生效，更小时维持当前值以避免截断已借出的令牌。"""
    monkeypatch.setattr(settings, "API_THREAD_LIMIT", 0)
    monkeypatch.setattr(
        type(settings), "CONF", property(lambda self: SimpleNamespace(threadpool=77))
    )

    async def scenario():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        try:
            limiter.total_tokens = 5
            thread_module.configure_default_thread_limiter()
            grown = limiter.total_tokens

            limiter.total_tokens = 1000
            thread_module.configure_default_thread_limiter()
            unchanged = limiter.total_tokens
            return grown, unchanged
        finally:
            limiter.total_tokens = original

    grown, unchanged = asyncio.run(scenario())

    assert grown == 77
    assert unchanged == 1000


def test_lifecycle_manifest_includes_thread_limiter_before_router_and_modules():
    """并发线程槽组件必须在正常和安全模式下都启用，且早于路由与模块服务启动。"""
    app = FastAPI()
    normal = lifecycle.get_lifecycle_manifest(app, safe_mode=False)
    safe = lifecycle.get_lifecycle_manifest(app, safe_mode=True)

    normal_by_name = {item["name"]: item for item in normal}
    safe_names = {item["name"] for item in safe}

    assert "并发线程槽" in normal_by_name
    assert "并发线程槽" in safe_names
    assert normal_by_name["并发线程槽"]["mode"] == "always"

    thread_limiter_order = normal_by_name["并发线程槽"]["start_order"]
    router_order = normal_by_name["路由"]["start_order"]
    modules_order = normal_by_name["模块服务"]["start_order"]

    assert thread_limiter_order is not None
    assert thread_limiter_order < router_order
    assert thread_limiter_order < modules_order
