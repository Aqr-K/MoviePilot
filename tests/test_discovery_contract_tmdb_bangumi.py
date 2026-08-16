"""TheMovieDb 与 Bangumi 的发现能力契约。

两源的既有发现方法都是榜单契约的退化情形：``tmdb_trending`` 只有 ``page`` 没有 ``count``，
``bangumi_calendar`` 无参且不支持翻页。契约不能因此走样——榜单声明里的 ``paged`` 正是为
后者存在，调用方据此决定是否翻页。

``discover_board`` 一律委托给既有榜单方法，取数路径与缓存、限流的挂载点保持一致，不因
归一而退化成整个 ``discover_board`` 一个桶。
"""
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.modules.recognizers.bangumi import BangumiModule
from app.modules.recognizers.themoviedb import TheMovieDbModule
from app.schemas.types import MediaSource, MediaType


@pytest.fixture
def tmdb() -> TheMovieDbModule:
    """构造接口客户端被打桩的 TheMovieDb 模块。"""
    instance = TheMovieDbModule()
    instance.tmdb = Mock()
    instance.tmdb.discover_trending.return_value = [{"id": 1, "media_type": MediaType.MOVIE}]
    instance.tmdb.discover_movies.return_value = [{"id": 2, "media_type": MediaType.MOVIE}]
    instance.tmdb.discover_tvs.return_value = [{"id": 3, "media_type": MediaType.TV}]
    return instance


@pytest.fixture
def bangumi() -> BangumiModule:
    """构造接口客户端被打桩的 Bangumi 模块。"""
    instance = BangumiModule()
    instance.bangumiapi = Mock()
    instance.bangumiapi.calendar.return_value = [{"id": 1, "name": "A", "name_cn": "甲"}]
    instance.bangumiapi.discover.return_value = [{"id": 2, "name": "B", "name_cn": "乙"}]
    return instance


@pytest.fixture(params=["tmdb", "bangumi"])
def module(request):
    """逐个取两源的模块实例，契约校验对两源同等生效。"""
    return request.getfixturevalue(request.param)


def source_of(module) -> MediaSource:
    """
    取模块自报的来源

    :param module: 模块实例
    :return: 榜单清单里声明的来源
    """
    return module.discover_boards()[0].source


def test_a_board_declares_its_source_identity_and_paging(module):
    """榜单清单带出所属来源、标识、显示名与是否支持翻页。"""
    boards = module.discover_boards()

    assert boards
    for board in boards:
        assert isinstance(board, schemas.DiscoverBoard)
        assert board.source in (MediaSource.TMDB, MediaSource.Bangumi)
        assert board.board and board.name
        assert isinstance(board.paged, bool)


def test_every_declared_board_can_be_fetched(module):
    """声明出来的每个榜单都取得到内容，清单与实现不得脱节。"""
    source = source_of(module)

    for board in module.discover_boards():
        assert module.discover_board(source=source, board=board.board) is not None


def test_a_board_of_another_source_is_declined(module):
    """来源不是本源时返回 None，让广播继续问下一个模块。"""
    for board in module.discover_boards():
        assert module.discover_board(source=MediaSource.AniList, board=board.board) is None


def test_an_unknown_board_is_declined(module):
    """本源不认识的榜单标识返回 None，不抛错。"""
    assert module.discover_board(source=source_of(module), board="not_a_board") is None


def test_a_board_without_a_source_is_declined(module):
    """来源缺省时不认领，广播里没有默认归属。"""
    assert module.discover_board(board="trending") is None


def test_discover_of_another_source_is_declined(module):
    """条件筛选同样按来源自检。"""
    assert module.discover(source=MediaSource.Douban) is None


def test_a_board_is_fetched_through_the_existing_method(module):
    """取榜单委托给既有榜单方法，缓存与限流仍挂在原来的取数路径上。"""
    source = source_of(module)

    for board, (_, method, _, _) in module._BOARDS.items():  # noqa: SLF001
        with patch.object(module, method, autospec=True, return_value=[]) as fetch:
            result = module.discover_board(source=source, board=board)

        assert result == []
        fetch.assert_called_once()


def test_tmdb_declares_a_mixed_content_board(tmdb):
    """流行趋势混合电影与电视剧，媒体类型为空。"""
    boards = {board.board: board for board in tmdb.discover_boards()}

    assert boards["trending"].media_type is None
    assert boards["trending"].paged is True


def test_tmdb_board_paging_reaches_the_client(tmdb):
    """页码原样传到接口客户端。"""
    tmdb.discover_board(source=MediaSource.TMDB, board="trending", page=3)

    tmdb.tmdb.discover_trending.assert_called_once_with(page=3)


def test_tmdb_board_count_does_not_disturb_paging(tmdb):
    """TMDB 每页条数由接口固定，count 不参与取数，同一页取几次内容一致。"""
    default_count = tmdb.discover_board(source=MediaSource.TMDB, board="trending", page=2)
    given_count = tmdb.discover_board(source=MediaSource.TMDB, board="trending", page=2, count=5)

    assert len(default_count) == len(given_count)
    assert {call.kwargs["page"] for call in tmdb.tmdb.discover_trending.call_args_list} == {2}


def test_tmdb_discover_fills_the_criteria_it_was_not_given(tmdb):
    """未给出的筛选条件按不过滤取值，缺条件不至于取不到数。"""
    result = tmdb.discover(source=MediaSource.TMDB, mtype=MediaType.MOVIE)

    assert result
    tmdb.tmdb.discover_movies.assert_called_once()


def test_tmdb_discover_passes_the_given_criteria(tmdb):
    """给出的筛选条件透传到接口客户端。"""
    tmdb.discover(source=MediaSource.TMDB, mtype=MediaType.TV, with_genres="16", page=2)

    params = tmdb.tmdb.discover_tvs.call_args.args[0]
    assert params["with_genres"] == "16"
    assert params["page"] == 2


def test_bangumi_declares_an_unpaged_board(bangumi):
    """放送表是整周的固定内容，不支持翻页，内容是电视剧。"""
    boards = {board.board: board for board in bangumi.discover_boards()}

    assert boards["calendar"].paged is False
    assert boards["calendar"].media_type == MediaType.TV


def test_bangumi_board_has_no_second_page(bangumi):
    """不支持翻页的榜单第二页起为空，与来源不匹配的 None 区分开。"""
    result = bangumi.discover_board(source=MediaSource.Bangumi, board="calendar", page=2)

    assert result == []
    bangumi.bangumiapi.calendar.assert_not_called()


def test_bangumi_discover_passes_the_given_criteria(bangumi):
    """条件筛选把本源自有的条件透传给接口客户端。"""
    result = bangumi.discover(source=MediaSource.Bangumi, type=2, sort="rank")

    assert result
    bangumi.bangumiapi.discover.assert_called_once_with(type=2, sort="rank")


def test_the_legacy_methods_still_work(tmdb, bangumi):
    """契约化期间旧方法保留，便于前后对照验证归一无损。"""
    assert tmdb.tmdb_trending(page=1)
    assert tmdb.tmdb_discover(mtype=MediaType.MOVIE, sort_by="popularity.desc", with_genres="",
                              with_original_language="", with_keywords="",
                              with_watch_providers="", vote_average=0.0, vote_count=0,
                              release_date="")
    assert bangumi.bangumi_calendar()
    assert bangumi.bangumi_discover(type=2)
