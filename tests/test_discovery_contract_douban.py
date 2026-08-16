"""豆瓣的发现能力契约。

豆瓣是榜单最多的发现源，7 个榜单经 ``discover_board(board=...)`` 统一取用，条件筛选经
``discover(**criteria)`` 统一入口，两者都按 ``source`` 自检，不是本源时返回 None。

每个榜单的缓存与限流挂在各自的取数方法上。``discover_board`` 按标识委托到这些方法而不
自行取数，限流桶因此仍以榜单为粒度，不会退化成整个 ``discover_board`` 一个桶。
"""
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.modules.recognizers.douban import DoubanModule
from app.schemas.types import MediaSource, MediaType

# 契约期望：榜单标识 -> (内容媒体类型, 是否支持翻页, 取数方法名)
EXPECTED_BOARDS = {
    "movie_showing": (MediaType.MOVIE, True, "movie_showing"),
    "movie_hot": (MediaType.MOVIE, True, "movie_hot"),
    "movie_top250": (MediaType.MOVIE, True, "movie_top250"),
    "tv_hot": (MediaType.TV, True, "tv_hot"),
    "tv_weekly_chinese": (MediaType.TV, True, "tv_weekly_chinese"),
    "tv_weekly_global": (MediaType.TV, True, "tv_weekly_global"),
    "tv_animation": (MediaType.TV, True, "tv_animation"),
}

# 榜单标识 -> 接口客户端上对应的取数方法名
BOARD_ENDPOINTS = {
    "movie_showing": "movie_showing",
    "movie_hot": "movie_hot_gaia",
    "movie_top250": "movie_top250",
    "tv_hot": "tv_hot",
    "tv_weekly_chinese": "tv_chinese_best_weekly",
    "tv_weekly_global": "tv_global_best_weekly",
    "tv_animation": "tv_animation",
}

ITEM = {
    "id": "1",
    "title": "测试条目",
    "type": "movie",
    "year": "2024",
    "pic": {"large": "https://img/large.jpg", "normal": "https://img/normal.jpg"},
}


@pytest.fixture
def module() -> DoubanModule:
    """构造接口客户端被打桩的豆瓣模块。"""
    instance = DoubanModule()
    instance.doubanapi = Mock()
    for endpoint in set(BOARD_ENDPOINTS.values()):
        getattr(instance.doubanapi, endpoint).return_value = {"subject_collection_items": [ITEM]}
    instance.doubanapi.movie_recommend.return_value = {"items": [ITEM]}
    instance.doubanapi.tv_recommend.return_value = {"items": [ITEM]}
    return instance


def test_the_board_list_covers_every_expected_board(module):
    """榜单清单不多不少正是这 7 个，且都归属豆瓣来源。"""
    boards = module.discover_boards()

    assert {board.board for board in boards} == set(EXPECTED_BOARDS)
    for board in boards:
        assert isinstance(board, schemas.DiscoverBoard)
        assert board.source == MediaSource.Douban
        assert board.name


def test_each_board_declares_its_media_type_and_paging(module):
    """每个榜单声明的媒体类型与翻页能力与其内容一致。"""
    for board in module.discover_boards():
        media_type, paged, _ = EXPECTED_BOARDS[board.board]
        assert board.media_type == media_type
        assert board.paged is paged


def test_every_declared_board_can_be_fetched(module):
    """声明出来的每个榜单都取得到内容，清单与实现不得脱节。"""
    for board in module.discover_boards():
        result = module.discover_board(source=MediaSource.Douban, board=board.board)
        assert result
        assert result[0].douban_id == "1"


def test_each_board_is_served_by_its_own_fetch_method(module):
    """每个榜单委托到自己的取数方法，限流与缓存因此仍按榜单分桶。"""
    for board, (_, _, fetch_name) in EXPECTED_BOARDS.items():
        with patch.object(DoubanModule, fetch_name, return_value=[]) as fetch:
            module.discover_board(source=MediaSource.Douban, board=board, page=2, count=10)
        fetch.assert_called_once_with(page=2, count=10)


def test_board_paging_reaches_the_client(module):
    """翻页参数换算成起始位置后传到接口客户端。"""
    module.discover_board(source=MediaSource.Douban, board="movie_top250", page=3, count=15)

    module.doubanapi.movie_top250.assert_called_once_with(start=30, count=15)


def test_a_board_of_another_source_is_declined(module):
    """来源不是本源时返回 None，让广播继续问下一个模块。"""
    assert module.discover_board(source=MediaSource.TMDB, board="movie_hot") is None


def test_a_board_of_douban_music_is_declined(module):
    """豆瓣音乐是独立来源，其请求不由影视模块承接。"""
    assert module.discover_board(source=MediaSource.DoubanMusic, board="movie_hot") is None


def test_a_board_without_a_source_is_declined(module):
    """来源缺省时不承接，避免广播里被误当成本源。"""
    assert module.discover_board(board="movie_hot") is None


def test_an_unknown_board_is_declined(module):
    """本源不认识的榜单标识返回 None，不抛错。"""
    assert module.discover_board(source=MediaSource.Douban, board="not_a_board") is None


def test_discover_filters_movies_by_criteria(module):
    """条件筛选把排序、标签与翻页透传给电影探索接口。"""
    result = module.discover(source=MediaSource.Douban, mtype=MediaType.MOVIE,
                             sort="U", tags="喜剧", page=2, count=10)

    assert result
    module.doubanapi.movie_recommend.assert_called_once_with(start=10, count=10,
                                                             sort="U", tags="喜剧")


def test_discover_filters_tvs_by_criteria(module):
    """剧集条件筛选走剧集探索接口。"""
    module.discover(source=MediaSource.Douban, mtype=MediaType.TV, sort="R", tags="日剧")

    module.doubanapi.tv_recommend.assert_called_once_with(start=0, count=30,
                                                          sort="R", tags="日剧")


def test_discover_without_criteria_uses_the_client_defaults(module):
    """未给条件时按接口默认的排序与标签取电影。"""
    module.discover(source=MediaSource.Douban)

    module.doubanapi.movie_recommend.assert_called_once_with(start=0, count=30,
                                                             sort="R", tags="")


def test_discover_is_served_by_the_existing_filter_method(module):
    """条件筛选委托到自己的取数方法，限流与缓存不被绕开。"""
    with patch.object(DoubanModule, "douban_discover", return_value=[]) as fetch:
        module.discover(source=MediaSource.Douban, mtype=MediaType.TV, tags="悬疑")

    fetch.assert_called_once_with(mtype=MediaType.TV, sort="R", tags="悬疑")


def test_discover_of_another_source_is_declined(module):
    """条件筛选同样按来源自检。"""
    assert module.discover(source=MediaSource.Bangumi, mtype=MediaType.MOVIE) is None
    assert module.discover() is None


def test_the_board_methods_still_work(module):
    """7 个榜单方法各自可用。"""
    for fetch_name in (declared[2] for declared in EXPECTED_BOARDS.values()):
        assert getattr(module, fetch_name)(page=1, count=30)


def test_the_filter_method_still_works(module):
    """条件筛选方法可用。"""
    assert module.douban_discover(mtype=MediaType.MOVIE, sort="R", tags="", page=1, count=30)
