"""发现能力契约。

15 个发现方法此前各自为政、名字带源前缀，``chain/recommend.py`` 只能硬编码 11 个方法名
点调。它们的签名其实只有两种形状：榜单取页 ``(page, count)`` 与条件筛选
``(mtype, **criteria)``，返回类型全是 ``List[MediaInfo]``。

契约化后新增一个发现源只需实现三个方法，chain 不必再认识具体源。分发沿用识别侧的既有
模式：广播加按来源自检，不匹配返回 None；``discover_boards`` 相反，各源榜单的并集正是
前端要枚举的全部，广播累加就是它要的语义。

本文件覆盖 AniList 源，其余三源各有自己的契约测试。
"""
import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app import schemas
from app.modules.recognizers.anilist import AniListModule
from app.schemas.types import MediaSource, MediaType


def run(coro):
    """
    在同步测试函数里驱动协程

    :param coro: 待驱动的协程
    :return: 协程的返回值
    """
    return asyncio.run(coro)


@pytest.fixture
def module() -> AniListModule:
    """构造接口客户端被打桩的 AniList 模块。"""
    instance = AniListModule()
    instance.anilist_api = Mock()
    instance.anilist_api.trending.return_value = [{"id": 1, "format": "TV"}]
    instance.anilist_api.popular_this_season.return_value = [{"id": 2, "format": "TV"}]
    instance.anilist_api.discover.return_value = [{"id": 3, "format": "MOVIE"}]
    instance.anilist_api.async_trending = AsyncMock(return_value=[{"id": 1, "format": "TV"}])
    instance.anilist_api.async_popular_this_season = AsyncMock(
        return_value=[{"id": 2, "format": "TV"}]
    )
    instance.anilist_api.async_discover = AsyncMock(return_value=[{"id": 3, "format": "MOVIE"}])
    return instance


def test_a_board_declares_its_source_identity_and_paging(module):
    """榜单清单带出所属来源、标识、显示名与是否支持翻页。"""
    boards = module.discover_boards()

    assert boards
    for board in boards:
        assert isinstance(board, schemas.DiscoverBoard)
        assert board.source == MediaSource.AniList
        assert board.board and board.name
        assert isinstance(board.paged, bool)


def test_every_declared_board_can_be_fetched(module):
    """声明出来的每个榜单都取得到内容，清单与实现不得脱节。"""
    for board in module.discover_boards():
        assert module.discover_board(source=MediaSource.AniList, board=board.board) is not None


def test_a_board_of_another_source_is_declined(module):
    """来源不是本源时返回 None，让广播继续问下一个模块。"""
    assert module.discover_board(source=MediaSource.TMDB, board="trending") is None


def test_an_unknown_board_is_declined(module):
    """本源不认识的榜单标识返回 None，不抛错。"""
    assert module.discover_board(source=MediaSource.AniList, board="not_a_board") is None


def test_board_paging_reaches_the_client(module):
    """翻页参数原样传到接口客户端。"""
    module.discover_board(source=MediaSource.AniList, board="trending", page=3, count=15)

    module.anilist_api.trending.assert_called_once_with(page=3, count=15)


def test_discover_filters_by_criteria(module):
    """条件筛选把条件透传给接口客户端，并返回统一媒体信息。"""
    result = module.discover(source=MediaSource.AniList, mtype=MediaType.TV, season="WINTER")

    assert isinstance(result, list)
    module.anilist_api.discover.assert_called_once()


def test_discover_of_another_source_is_declined(module):
    """条件筛选同样按来源自检。"""
    assert module.discover(source=MediaSource.Douban) is None


def test_the_fetch_methods_behind_the_contract_still_work(module):
    """契约背后的两个榜单取数方法自身可用，与契约的逐条对照才成立。"""
    assert module._anilist_trending(page=1, count=20)
    assert module._anilist_popular_this_season(page=1, count=20)


def test_every_declared_board_can_be_fetched_asynchronously(module):
    """异步取榜单同样覆盖清单里的每个榜单。"""
    for board in module.discover_boards():
        result = run(module.async_discover_board(source=MediaSource.AniList, board=board.board))
        assert result is not None


def test_an_asynchronous_board_of_another_source_is_declined(module):
    """异步取榜单按来源自检，不是本源时返回 None。"""
    assert run(module.async_discover_board(source=MediaSource.TMDB, board="trending")) is None


def test_an_asynchronous_board_without_a_source_is_declined(module):
    """来源缺省时异步取榜单不认领。"""
    assert run(module.async_discover_board(board="trending")) is None


def test_an_unknown_asynchronous_board_is_declined(module):
    """异步取榜单遇到本源不认识的标识返回 None，不抛错。"""
    assert run(module.async_discover_board(source=MediaSource.AniList, board="not_a_board")) is None


def test_an_asynchronous_board_is_fetched_through_the_existing_method(module):
    """异步取榜单委托到既有的异步取数方法，缓存与限流仍挂在原来的取数路径上。"""
    for board, (_, endpoint, _) in module._BOARDS.items():  # noqa: SLF001
        target = f"_async_anilist_{endpoint}"
        with patch.object(module, target, new_callable=AsyncMock, return_value=[]) as fetch:
            result = run(module.async_discover_board(source=MediaSource.AniList, board=board))

        assert result == []
        fetch.assert_awaited_once()


def test_asynchronous_board_paging_reaches_the_client(module):
    """异步取榜单的翻页参数原样传到接口客户端。"""
    run(module.async_discover_board(source=MediaSource.AniList, board="trending",
                                    page=3, count=15))

    module.anilist_api.async_trending.assert_awaited_once_with(page=3, count=15)


def test_asynchronous_discover_filters_by_criteria(module):
    """异步条件筛选把条件透传给接口客户端，并返回统一媒体信息。"""
    result = run(module.async_discover(source=MediaSource.AniList, mtype=MediaType.TV,
                                       season="WINTER"))

    assert isinstance(result, list)
    module.anilist_api.async_discover.assert_awaited_once_with(mtype=MediaType.TV, season="WINTER")


def test_asynchronous_discover_of_another_source_is_declined(module):
    """异步条件筛选同样按来源自检。"""
    assert run(module.async_discover(source=MediaSource.Douban)) is None


def test_asynchronous_discover_is_served_by_the_existing_method(module):
    """异步条件筛选委托到既有的异步取数方法，不绕开缓存与限流。"""
    with patch.object(module, "_async_anilist_discover",
                      new_callable=AsyncMock, return_value=[]) as fetch:
        result = run(module.async_discover(source=MediaSource.AniList, season="WINTER"))

    assert result == []
    fetch.assert_awaited_once_with(season="WINTER")


def test_the_asynchronous_board_agrees_with_the_synchronous_one(module):
    """同一榜单同一页，异步与同步取到同样的内容。"""
    for board in module.discover_boards():
        synchronous = module.discover_board(source=MediaSource.AniList, board=board.board, page=2)
        asynchronous = run(module.async_discover_board(source=MediaSource.AniList,
                                                       board=board.board, page=2))

        assert [media.anilist_id for media in asynchronous] == \
               [media.anilist_id for media in synchronous]
