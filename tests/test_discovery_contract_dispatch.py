"""chain 层按发现契约分发。

chain 不再认识 15 个带源前缀的专有方法名，榜单走 ``discover_board(source, board, page,
count)``，条件筛选走 ``discover(source, mtype, **criteria)``。两条路径与各源的专有方法必须
返回逐条相同的内容，归一才算无损。

``discover_board`` 对所有榜单一律接受 ``page``/``count``：``paged`` 声明的是数据源侧是否
原生分页，不是调用方能不能翻页。Bangumi 每日放送在源侧整周返回，仍要按页码切片给出对应
的一页。
"""
import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.chain import ChainBase
from app.chain.bangumi import BangumiChain
from app.chain.recommend import RecommendChain
from app.modules.recognizers.anilist import AniListModule
from app.modules.recognizers.bangumi import BangumiModule
from app.modules.recognizers.douban import DoubanModule
from app.modules.recognizers.themoviedb import TheMovieDbModule
from app.runtime.cache import TTLCache
from app.schemas.types import MediaSource, MediaType

# 豆瓣榜单标识 -> 接口客户端上对应的取数方法名
DOUBAN_BOARD_ENDPOINTS = {
    "movie_showing": "movie_showing",
    "movie_hot": "movie_hot_gaia",
    "movie_top250": "movie_top250",
    "tv_hot": "tv_hot",
    "tv_weekly_chinese": "tv_chinese_best_weekly",
    "tv_weekly_global": "tv_global_best_weekly",
    "tv_animation": "tv_animation",
}

# TMDB 条件筛选的一组完整取值
TMDB_CRITERIA = {
    "sort_by": "popularity.desc",
    "with_genres": "16",
    "with_original_language": "ja",
    "with_keywords": "210024",
    "with_watch_providers": "8",
    "vote_average": 7.0,
    "vote_count": 100,
    "release_date": "2024-01-01",
    "page": 2,
}


def run(coro):
    """
    在同步测试函数里驱动协程

    :param coro: 待驱动的协程
    :return: 协程的返回值
    """
    return asyncio.run(coro)


@pytest.fixture
def isolated_recommend_cache():
    """用例前后都清空推荐缓存，避免缓存装饰器串味。"""
    TTLCache(region=RecommendChain.recommend_cache_region).clear()
    yield
    TTLCache(region=RecommendChain.recommend_cache_region).clear()


def digest(medias) -> list:
    """
    把媒体信息列表压成可逐条比对的形态

    :param medias: 统一媒体信息列表
    :return: 每条媒体信息的字典形态组成的列表
    """
    assert medias is not None
    return [media.to_dict() for media in medias]


def douban_item(index: int) -> dict:
    """
    构造一条豆瓣条目桩数据

    :param index: 条目序号
    :return: 豆瓣接口返回形态的条目
    """
    return {
        "id": str(index),
        "title": f"豆瓣条目{index}",
        "type": "movie",
        "year": "2024",
        "pic": {"large": "https://img/large.jpg", "normal": "https://img/normal.jpg"},
    }


@pytest.fixture
def douban() -> DoubanModule:
    """构造接口客户端被打桩的豆瓣模块。"""
    instance = DoubanModule()
    instance.doubanapi = Mock()
    payload = {"subject_collection_items": [douban_item(1), douban_item(2)]}
    for endpoint in set(DOUBAN_BOARD_ENDPOINTS.values()):
        getattr(instance.doubanapi, endpoint).return_value = payload
        setattr(instance.doubanapi, f"async_{endpoint}", AsyncMock(return_value=payload))
    instance.doubanapi.movie_recommend.return_value = {"items": [douban_item(3)]}
    instance.doubanapi.tv_recommend.return_value = {"items": [douban_item(4)]}
    instance.doubanapi.async_movie_recommend = AsyncMock(return_value={"items": [douban_item(3)]})
    instance.doubanapi.async_tv_recommend = AsyncMock(return_value={"items": [douban_item(4)]})
    return instance


@pytest.fixture
def tmdb() -> TheMovieDbModule:
    """构造接口客户端被打桩的 TheMovieDb 模块。"""
    instance = TheMovieDbModule()
    instance.tmdb = Mock()
    trending = [{"id": 1, "media_type": MediaType.MOVIE}]
    movies = [{"id": 2, "media_type": MediaType.MOVIE}]
    tvs = [{"id": 3, "media_type": MediaType.TV}]
    instance.tmdb.discover_trending.return_value = trending
    instance.tmdb.discover_movies.return_value = movies
    instance.tmdb.discover_tvs.return_value = tvs
    instance.tmdb.async_discover_trending = AsyncMock(return_value=trending)
    instance.tmdb.async_discover_movies = AsyncMock(return_value=movies)
    instance.tmdb.async_discover_tvs = AsyncMock(return_value=tvs)
    return instance


@pytest.fixture
def anilist() -> AniListModule:
    """构造接口客户端被打桩的 AniList 模块。"""
    instance = AniListModule()
    instance.anilist_api = Mock()
    trending = [{"id": 1, "format": "TV"}]
    season = [{"id": 2, "format": "TV"}]
    discovered = [{"id": 3, "format": "MOVIE"}]
    instance.anilist_api.trending.return_value = trending
    instance.anilist_api.popular_this_season.return_value = season
    instance.anilist_api.discover.return_value = discovered
    instance.anilist_api.async_trending = AsyncMock(return_value=trending)
    instance.anilist_api.async_popular_this_season = AsyncMock(return_value=season)
    instance.anilist_api.async_discover = AsyncMock(return_value=discovered)
    return instance


# 每日放送桩数据的条目总数，取大于每页条数以便验证第二页
CALENDAR_TOTAL = 70
# 每日放送分页验证使用的每页条数
CALENDAR_COUNT = 30


@pytest.fixture
def bangumi() -> BangumiModule:
    """构造接口客户端被打桩的 Bangumi 模块，放送表条目数大于一页。"""
    instance = BangumiModule()
    instance.bangumiapi = Mock()
    calendar = [
        {"id": index, "name": f"A{index}", "name_cn": f"甲{index}"}
        for index in range(CALENDAR_TOTAL)
    ]
    discovered = [{"id": 900, "name": "B", "name_cn": "乙"}]
    instance.bangumiapi.calendar.return_value = calendar
    instance.bangumiapi.discover.return_value = discovered
    instance.bangumiapi.async_calendar = AsyncMock(return_value=calendar)
    instance.bangumiapi.async_discover = AsyncMock(return_value=discovered)
    return instance


def wire_chain(chain, *modules):
    """
    把处理链与真实模块、插件运行态隔离，按方法名广播到给定的模块替身

    :param chain: 处理链实例
    :param modules: 参与广播的模块实例
    :return: 接好模块替身的处理链
    """
    chain.pluginmanager = Mock()
    chain.pluginmanager.running_plugins = {}
    chain.modulemanager = Mock()
    chain.modulemanager.get_running_modules.side_effect = \
        lambda method: [m for m in modules if callable(getattr(m, method, None))]
    chain.messagehelper = Mock()
    chain.eventmanager = Mock()
    return chain


def build_chain(*modules) -> ChainBase:
    """
    构造与真实模块、插件运行态隔离的 ChainBase

    :param modules: 参与广播的模块实例
    :return: 链基类实例
    """
    return wire_chain(ChainBase(), *modules)


class TestBroadcastDispatch:
    """广播到四个源时的分发行为"""

    def test_only_the_named_source_answers_a_board(self, douban, tmdb, anilist, bangumi):
        """榜单广播到四个源，只有 source 指名的那个给出内容。"""
        chain = build_chain(douban, tmdb, anilist, bangumi)

        result = chain.run_module("discover_board", source=MediaSource.TMDB,
                                  board="trending", page=1, count=30)

        assert digest(result) == digest(tmdb._tmdb_trending(page=1))

    def test_only_the_named_source_answers_a_filter(self, douban, tmdb, anilist, bangumi):
        """条件筛选广播到四个源，只有 source 指名的那个给出内容。"""
        chain = build_chain(douban, tmdb, anilist, bangumi)

        result = chain.run_module("discover", source=MediaSource.Douban,
                                  mtype=MediaType.MOVIE, sort="R", tags="", page=1, count=30)

        assert digest(result) == digest(
            douban._douban_discover(mtype=MediaType.MOVIE, sort="R", tags="", page=1, count=30)
        )

    def test_a_board_broadcast_carries_the_rate_limit_flag(self, douban, tmdb, anilist, bangumi):
        """榜单广播带 raise_exception 时四个源都收得下，不因签名不认识该参数而报错。"""
        chain = build_chain(douban, tmdb, anilist, bangumi)

        result = run(chain.async_run_module(
            "async_discover_board", source=MediaSource.TMDB, board="trending",
            page=1, count=30, raise_exception=True,
        ))

        assert digest(result) == digest(run(tmdb._async_tmdb_trending(page=1)))

    def test_a_filter_broadcast_carries_the_rate_limit_flag(self, douban, tmdb, anilist, bangumi):
        """条件筛选广播带 raise_exception 时四个源都收得下。"""
        chain = build_chain(douban, tmdb, anilist, bangumi)

        result = run(chain.async_run_module(
            "async_discover", source=MediaSource.TMDB, mtype=MediaType.MOVIE,
            raise_exception=True, **TMDB_CRITERIA,
        ))

        assert digest(result) == digest(run(tmdb._async_tmdb_discover(
            mtype=MediaType.MOVIE, **TMDB_CRITERIA
        )))

    def test_the_rate_limit_flag_reaches_the_tmdb_client(self, tmdb):
        """raise_exception 一路透传到 TMDB 接口客户端，上游失败才抛得出来。"""
        run(tmdb.async_discover_board(source=MediaSource.TMDB, board="trending",
                                      page=1, count=30, raise_exception=True))
        run(tmdb.async_discover(source=MediaSource.TMDB, mtype=MediaType.MOVIE,
                                raise_exception=True, **TMDB_CRITERIA))

        assert tmdb.tmdb.async_discover_trending.await_args.kwargs["raise_exception"] is True
        assert tmdb.tmdb.async_discover_movies.await_args.kwargs["raise_exception"] is True


class TestCalendarPaging:
    """每日放送的翻页行为"""

    def test_calendar_second_page_is_not_empty(self, bangumi):
        """放送表第二页给出第二页内容，不因源侧不原生分页而返回空。"""
        page_two = bangumi.discover_board(
            source=MediaSource.Bangumi, board="calendar",
            page=2, count=CALENDAR_COUNT,
        )

        assert len(page_two) == CALENDAR_COUNT
        assert [media.bangumi_id for media in page_two] == list(
            range(CALENDAR_COUNT, CALENDAR_COUNT * 2)
        )

    def test_async_calendar_second_page_is_not_empty(self, bangumi):
        """异步取放送表第二页同样给出第二页内容。"""
        page_two = run(bangumi.async_discover_board(
            source=MediaSource.Bangumi, board="calendar",
            page=2, count=CALENDAR_COUNT,
        ))

        assert len(page_two) == CALENDAR_COUNT
        assert [media.bangumi_id for media in page_two] == list(
            range(CALENDAR_COUNT, CALENDAR_COUNT * 2)
        )

    def test_calendar_last_page_is_partial(self, bangumi):
        """放送表末页给出剩余条目，超出总数的页码为空。"""
        last = bangumi.discover_board(source=MediaSource.Bangumi, board="calendar",
                                      page=3, count=CALENDAR_COUNT)
        beyond = bangumi.discover_board(source=MediaSource.Bangumi, board="calendar",
                                        page=4, count=CALENDAR_COUNT)

        assert len(last) == CALENDAR_TOTAL - CALENDAR_COUNT * 2
        assert beyond == []

    def test_calendar_declares_the_source_does_not_page(self, bangumi):
        """放送表声明源侧不原生分页，声明与可翻页互不冲突。"""
        declared = {board.board: board for board in bangumi.discover_boards()}

        assert declared["calendar"].paged is False

    @pytest.mark.parametrize("page", [1, 2, 3])
    def test_calendar_page_matches_slicing_the_legacy_result(self, bangumi, page):
        """同一页码下，契约取页与取全量再切片得到的内容逐条相同。"""
        legacy = bangumi._bangumi_calendar()
        expected = legacy[(page - 1) * CALENDAR_COUNT: page * CALENDAR_COUNT]

        contract = bangumi.discover_board(source=MediaSource.Bangumi, board="calendar",
                                          page=page, count=CALENDAR_COUNT)

        assert digest(contract) == digest(expected)

    @pytest.mark.parametrize("page", [1, 2, 3])
    def test_async_calendar_page_matches_slicing_the_legacy_result(self, bangumi, page):
        """异步路径下，契约取页与取全量再切片得到的内容逐条相同。"""
        legacy = run(bangumi._async_bangumi_calendar())
        expected = legacy[(page - 1) * CALENDAR_COUNT: page * CALENDAR_COUNT]

        contract = run(bangumi.async_discover_board(
            source=MediaSource.Bangumi, board="calendar",
            page=page, count=CALENDAR_COUNT,
        ))

        assert digest(contract) == digest(expected)


class TestCalendarThroughTheChain:
    """每日放送经处理链取用时的翻页行为"""

    def test_the_bangumi_chain_returns_the_whole_week(self, bangumi):
        """``BangumiChain.calendar`` 取整周放送，不被每页条数截断。"""
        chain = wire_chain(BangumiChain(), bangumi)

        assert len(chain.calendar()) == CALENDAR_TOTAL
        assert len(run(chain.async_calendar())) == CALENDAR_TOTAL

    def test_the_recommend_chain_gets_the_second_page(self, bangumi, isolated_recommend_cache):
        """推荐链取放送表第二页时由数据源切片，端到端拿到的仍是第二页。"""
        async def dispatch(method, **kwargs):
            """把处理链的分发转接到打过桩的模块上"""
            return await getattr(bangumi, method)(**kwargs)

        with patch("app.chain.recommend.BangumiChain") as chain_class:
            chain_class.return_value.async_run_module = AsyncMock(side_effect=dispatch)
            result = run(RecommendChain().async_bangumi_calendar(page=2, count=CALENDAR_COUNT))

        assert [item["bangumi_id"] for item in result] == list(
            range(CALENDAR_COUNT, CALENDAR_COUNT * 2)
        )


class TestBoardParity:
    """榜单：专有方法与契约取到的内容一致"""

    @pytest.mark.parametrize("board", sorted(DOUBAN_BOARD_ENDPOINTS))
    def test_douban_board_matches_legacy_method(self, douban, board):
        """豆瓣 7 个榜单逐个对照，契约与专有方法结果逐条相同。"""
        legacy = getattr(douban, f"_{board}")(page=2, count=15)

        contract = douban.discover_board(source=MediaSource.Douban, board=board,
                                         page=2, count=15)

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("board", sorted(DOUBAN_BOARD_ENDPOINTS))
    def test_async_douban_board_matches_legacy_method(self, douban, board):
        """豆瓣 7 个榜单的异步路径同样逐条相同。"""
        legacy = run(getattr(douban, f"_async_{board}")(page=2, count=15))

        contract = run(douban.async_discover_board(source=MediaSource.Douban, board=board,
                                                   page=2, count=15))

        assert digest(contract) == digest(legacy)

    def test_tmdb_trending_matches_legacy_method(self, tmdb):
        """TMDB 流行趋势契约与专有方法结果逐条相同。"""
        legacy = tmdb._tmdb_trending(page=2)

        contract = tmdb.discover_board(source=MediaSource.TMDB, board="trending", page=2)

        assert digest(contract) == digest(legacy)

    def test_async_tmdb_trending_matches_legacy_method(self, tmdb):
        """TMDB 流行趋势异步路径逐条相同。"""
        legacy = run(tmdb._async_tmdb_trending(page=2))

        contract = run(tmdb.async_discover_board(source=MediaSource.TMDB,
                                                 board="trending", page=2))

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("board", ["trending", "popular_this_season"])
    def test_anilist_board_matches_legacy_method(self, anilist, board):
        """AniList 两个榜单契约与专有方法结果逐条相同。"""
        legacy = getattr(anilist, f"_anilist_{board}")(page=2, count=15)

        contract = anilist.discover_board(source=MediaSource.AniList, board=board,
                                          page=2, count=15)

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("board", ["trending", "popular_this_season"])
    def test_async_anilist_board_matches_legacy_method(self, anilist, board):
        """AniList 两个榜单的异步路径同样逐条相同。"""
        legacy = run(getattr(anilist, f"_async_anilist_{board}")(page=2, count=15))

        contract = run(anilist.async_discover_board(source=MediaSource.AniList, board=board,
                                                    page=2, count=15))

        assert digest(contract) == digest(legacy)


class TestDiscoverParity:
    """条件筛选：专有方法与契约取到的内容一致"""

    @pytest.mark.parametrize("mtype", [MediaType.MOVIE, MediaType.TV])
    def test_douban_discover_matches_legacy_method(self, douban, mtype):
        """豆瓣条件筛选契约与专有方法结果逐条相同。"""
        legacy = douban._douban_discover(mtype=mtype, sort="R", tags="喜剧", page=2, count=15)

        contract = douban.discover(source=MediaSource.Douban, mtype=mtype,
                                   sort="R", tags="喜剧", page=2, count=15)

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("mtype", [MediaType.MOVIE, MediaType.TV])
    def test_async_douban_discover_matches_legacy_method(self, douban, mtype):
        """豆瓣条件筛选异步路径逐条相同。"""
        legacy = run(douban._async_douban_discover(mtype=mtype, sort="R", tags="喜剧",
                                                   page=2, count=15))

        contract = run(douban.async_discover(source=MediaSource.Douban, mtype=mtype,
                                             sort="R", tags="喜剧", page=2, count=15))

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("mtype", [MediaType.MOVIE, MediaType.TV])
    def test_tmdb_discover_matches_legacy_method(self, tmdb, mtype):
        """TMDB 条件筛选契约与专有方法结果逐条相同。"""
        legacy = tmdb._tmdb_discover(mtype=mtype, **TMDB_CRITERIA)

        contract = tmdb.discover(source=MediaSource.TMDB, mtype=mtype, **TMDB_CRITERIA)

        assert digest(contract) == digest(legacy)

    @pytest.mark.parametrize("mtype", [MediaType.MOVIE, MediaType.TV])
    def test_async_tmdb_discover_matches_legacy_method(self, tmdb, mtype):
        """TMDB 条件筛选异步路径逐条相同。"""
        legacy = run(tmdb._async_tmdb_discover(mtype=mtype, **TMDB_CRITERIA))

        contract = run(tmdb.async_discover(source=MediaSource.TMDB, mtype=mtype, **TMDB_CRITERIA))

        assert digest(contract) == digest(legacy)

    def test_anilist_discover_matches_legacy_method(self, anilist):
        """AniList 条件筛选契约与专有方法结果逐条相同。"""
        legacy = anilist._anilist_discover(mtype=MediaType.TV, season="WINTER")

        contract = anilist.discover(source=MediaSource.AniList, mtype=MediaType.TV,
                                    season="WINTER")

        assert digest(contract) == digest(legacy)

    def test_async_anilist_discover_matches_legacy_method(self, anilist):
        """AniList 条件筛选异步路径逐条相同。"""
        legacy = run(anilist._async_anilist_discover(mtype=MediaType.TV, season="WINTER"))

        contract = run(anilist.async_discover(source=MediaSource.AniList, mtype=MediaType.TV,
                                              season="WINTER"))

        assert digest(contract) == digest(legacy)

    def test_bangumi_discover_matches_legacy_method(self, bangumi):
        """Bangumi 条件筛选契约与专有方法结果逐条相同。"""
        legacy = bangumi._bangumi_discover(type=2, sort="rank")

        contract = bangumi.discover(source=MediaSource.Bangumi, type=2, sort="rank")

        assert digest(contract) == digest(legacy)

    def test_async_bangumi_discover_matches_legacy_method(self, bangumi):
        """Bangumi 条件筛选异步路径逐条相同。"""
        legacy = run(bangumi._async_bangumi_discover(type=2, sort="rank"))

        contract = run(bangumi.async_discover(source=MediaSource.Bangumi, type=2, sort="rank"))

        assert digest(contract) == digest(legacy)
