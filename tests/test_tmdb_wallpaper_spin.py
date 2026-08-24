"""随机壁纸在无可用背景图时必须返回空而不是自旋。

`get_random_wallpager` 以 `while True` + `random.choice` 反复抽取，直到抽中带
`backdrop_path` 的条目为止。趋势榜整页都不带该字段时——`media_type=person` 的
条目天然没有背景图，TMDB 反代裁剪载荷时也会整页缺失——循环没有任何退出条件、
不休眠、不做 IO，是纯 Python 忙循环，会占满一个 CPU 核心。同步版本跑在 anyio
线程池上会永久占用一个 worker，异步版本则直接卡死事件循环。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.application.orchestration.tmdb import TmdbChain


def _wallpaper_chain(infos, *, is_async: bool) -> TmdbChain:
    """构造只替换趋势榜数据源的壁纸链，避开真实模块分发。"""
    chain = TmdbChain.__new__(TmdbChain)
    if is_async:
        async def _async_trending(*_args, **_kwargs):
            return infos

        chain.async_tmdb_trending = _async_trending
    else:
        chain.tmdb_trending = lambda *_args, **_kwargs: infos
    return chain


def _media(backdrop):
    return SimpleNamespace(backdrop_path=backdrop)


@pytest.mark.timeout(10)
def test_sync_wallpaper_returns_none_when_no_backdrop_available():
    """整页都没有背景图时同步版本返回空，不进入无界自旋。"""
    chain = _wallpaper_chain([_media(None), _media("")], is_async=False)

    assert chain.get_random_wallpager() is None


@pytest.mark.timeout(10)
def test_async_wallpaper_returns_none_when_no_backdrop_available():
    """整页都没有背景图时异步版本返回空，不卡死事件循环。"""
    chain = _wallpaper_chain([_media(None), _media("")], is_async=True)

    assert asyncio.run(chain.async_get_random_wallpager()) is None


@pytest.mark.timeout(10)
def test_sync_wallpaper_picks_from_available_backdrops():
    """存在背景图时只在带背景图的条目中挑选。"""
    chain = _wallpaper_chain([_media(None), _media("/a.jpg")], is_async=False)

    assert chain.get_random_wallpager() == "/a.jpg"


@pytest.mark.timeout(10)
def test_async_wallpaper_picks_from_available_backdrops():
    """异步版本同样只在带背景图的条目中挑选。"""
    chain = _wallpaper_chain([_media(None), _media("/b.jpg")], is_async=True)

    assert asyncio.run(chain.async_get_random_wallpager()) == "/b.jpg"


@pytest.mark.timeout(10)
def test_wallpaper_returns_none_on_empty_trending():
    """趋势榜为空时返回空。"""
    assert _wallpaper_chain([], is_async=False).get_random_wallpager() is None
    assert asyncio.run(
        _wallpaper_chain([], is_async=True).async_get_random_wallpager()
    ) is None
