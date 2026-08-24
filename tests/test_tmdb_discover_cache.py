"""discover_movies/discover_tv_shows 缓存容量与实时性策略测试。

TMDB discover 请求的筛选条件覆盖 genre/sort/page/rating/date 等多个维度，
@cached 的 maxsize 必须能容纳多组不同筛选条件，否则每次翻页或更换筛选条件
都会把此前缓存的结果挤出，命中率退化为 0。

discover 系列方法对 _request_obj/_async_request_obj 传入 call_cached=False，
使其请求始终绕过 TMDB 响应层的共享缓存，让 discover 命中筛选条件缓存前，
底层始终拿到实时数据；这是刻意设计（与 trending.py 一致），不属于缺陷，
本文件同时对该行为加固定回归用例。
"""
import asyncio

import pytest

from app.modules.themoviedb.tmdbv3api.objs.discover import Discover


@pytest.fixture
def discover():
    """构造绕过真实网络的 Discover 实例，并保证同步缓存区域用例前后清空。"""
    Discover.discover_movies.cache_clear()
    Discover.discover_tv_shows.cache_clear()
    instance = Discover()
    yield instance
    Discover.discover_movies.cache_clear()
    Discover.discover_tv_shows.cache_clear()


@pytest.fixture
def async_discover():
    """构造绕过真实网络的 Discover 实例，并保证异步缓存区域用例前后清空。"""
    asyncio.run(Discover.async_discover_movies.cache_clear())
    asyncio.run(Discover.async_discover_tv_shows.cache_clear())
    instance = Discover()
    yield instance
    asyncio.run(Discover.async_discover_movies.cache_clear())
    asyncio.run(Discover.async_discover_tv_shows.cache_clear())


def test_discover_movies_cache_holds_multiple_param_combinations(discover):
    """discover_movies 缓存必须能同时容纳多组筛选条件，重放最早一组参数应命中缓存。"""
    call_log = []

    def fake_request_obj(*args, **kwargs):
        call_log.append(kwargs)
        return [{"call": len(call_log)}]

    discover._request_obj = fake_request_obj

    params_list = [
        tuple({"sort_by": "popularity.desc", "page": page}.items())
        for page in range(1, 6)
    ]
    first_round = [discover.discover_movies(params) for params in params_list]
    assert len(call_log) == 5

    # 重放最早一组参数：若容量不足以容纳 5 组不同筛选条件，会被挤出并触发新的网络调用
    replay = discover.discover_movies(params_list[0])
    assert len(call_log) == 5
    assert replay == first_round[0]


def test_discover_tv_shows_cache_holds_multiple_param_combinations(discover):
    """discover_tv_shows 缓存同样必须能同时容纳多组筛选条件。"""
    call_log = []

    def fake_request_obj(*args, **kwargs):
        call_log.append(kwargs)
        return [{"call": len(call_log)}]

    discover._request_obj = fake_request_obj

    params_list = [
        tuple({"with_genres": str(genre)}.items()) for genre in range(1, 6)
    ]
    first_round = [discover.discover_tv_shows(params) for params in params_list]
    assert len(call_log) == 5

    replay = discover.discover_tv_shows(params_list[0])
    assert len(call_log) == 5
    assert replay == first_round[0]


def test_async_discover_tv_shows_cache_holds_multiple_param_combinations(async_discover):
    """异步版本 async_discover_tv_shows 的缓存容量修复同样生效。"""
    call_log = []

    async def fake_async_request_obj(*args, **kwargs):
        call_log.append(kwargs)
        return [{"call": len(call_log)}]

    async_discover._async_request_obj = fake_async_request_obj

    async def run():
        params_list = [
            tuple({"with_genres": str(genre)}.items()) for genre in range(1, 6)
        ]
        first_round = [
            await async_discover.async_discover_tv_shows(params) for params in params_list
        ]
        assert len(call_log) == 5

        replay = await async_discover.async_discover_tv_shows(params_list[0])
        assert len(call_log) == 5
        assert replay == first_round[0]

    asyncio.run(run())


def test_discover_movies_still_bypasses_low_level_request_cache(discover):
    """discover_movies 命中筛选条件缓存前的真实请求必须继续绕过 TMDB 响应层缓存（call_cached=False），
    以保证发现列表在筛选条件缓存过期后总能拿到实时数据；这是刻意设计，maxsize 修复不应改变它。
    """
    captured = {}

    def fake_request_obj(*args, **kwargs):
        captured.update(kwargs)
        return []

    discover._request_obj = fake_request_obj
    discover.discover_movies(tuple({"page": 1}.items()))

    assert captured.get("call_cached") is False
