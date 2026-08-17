"""发现榜单的双契约。

前四批归一的是「同一能力 × N 个源」的笛卡尔积，机械替换即可。榜单不是——它是一组
语义各异的能力：本周放送表、固定的 Top250、实时趋势，彼此不可通约。硬塞进一个
discover(board=...) 会把差异藏进字符串参数，调用方仍旧要靠猜。

所以是两个契约：

    discover_boards()                            本源有哪些榜单，可枚举
    discover_board(source, board, page, count)   取其中一个

分页正是不可通约之处，也是 paginated 存在的理由：

    douban   七个榜单  (page, count)
    tmdb     趋势      (page)      没有 count
    bangumi  放送表    ()          完全没有分页

不支持分页的源不能收到 page，传了就是 TypeError；而调用方要能提前知道这件事，不是
试出来的。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource


class DiscoverBoardsEnumerationTest(unittest.TestCase):
    """各源交出自己的榜单清单"""

    def test_douban_enumerates_its_boards(self):
        """豆瓣交出七个榜单，每个都带标识与显示名。"""
        from app.modules.douban import DoubanModule

        boards = object.__new__(DoubanModule).discover_boards()

        self.assertEqual(7, len(boards))
        identifiers = {b.board for b in boards}
        self.assertEqual(
            {"movie_showing", "movie_hot", "movie_top250",
             "tv_hot", "tv_animation", "tv_weekly_chinese", "tv_weekly_global"},
            identifiers)
        self.assertTrue(all(b.source == MediaSource.Douban.value for b in boards))
        self.assertTrue(all(b.name for b in boards))

    def test_bangumi_declares_its_board_as_unpaginated(self):
        """Bangumi 放送表没有分页，必须声明出来。"""
        from app.modules.bangumi import BangumiModule

        boards = object.__new__(BangumiModule).discover_boards()

        self.assertEqual(1, len(boards))
        self.assertEqual("calendar", boards[0].board)
        self.assertFalse(boards[0].paginated)

    def test_paginated_boards_declare_themselves_paginated(self):
        """支持分页的榜单如实声明。"""
        from app.modules.douban import DoubanModule

        boards = object.__new__(DoubanModule).discover_boards()

        self.assertTrue(all(b.paginated for b in boards))

    def test_anilist_and_tmdb_enumerate_their_boards(self):
        """AniList 两个、TMDB 一个。"""
        from app.modules.anilist import AniListModule
        from app.modules.themoviedb import TheMovieDbModule

        anilist_boards = object.__new__(AniListModule).discover_boards()
        tmdb_boards = object.__new__(TheMovieDbModule).discover_boards()

        self.assertEqual({"trending", "popular_this_season"},
                         {b.board for b in anilist_boards})
        self.assertEqual({"trending"}, {b.board for b in tmdb_boards})


class DiscoverBoardFetchTest(unittest.TestCase):
    """按标识取某个榜单"""

    def test_douban_routes_a_board_to_its_own_method(self):
        """榜单标识路由到本源对应方法，分页参数照常传。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.movie_top250 = Mock(return_value=["媒体"])

        result = module.discover_board(MediaSource.Douban, "movie_top250",
                                       page=2, count=10)

        self.assertEqual(["媒体"], result)
        module.movie_top250.assert_called_once_with(page=2, count=10)

    def test_an_unpaginated_board_is_not_handed_a_page(self):
        """不分页的榜单不能收到页码，传了会 TypeError。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_calendar = Mock(return_value=["媒体"])

        result = module.discover_board(MediaSource.Bangumi, "calendar",
                                       page=3, count=10)

        self.assertEqual(["媒体"], result)
        module.bangumi_calendar.assert_called_once_with()

    def test_a_board_without_a_page_size_is_not_handed_one(self):
        """TMDB 趋势只认页码，不认每页条数。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_trending = Mock(return_value=["媒体"])

        module.discover_board(MediaSource.TMDB, "trending", page=2, count=10)

        module.tmdb_trending.assert_called_once_with(page=2)

    def test_a_foreign_source_is_declined(self):
        """非本源的请求让出。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.movie_hot = Mock()

        self.assertIsNone(module.discover_board(MediaSource.TMDB, "movie_hot"))
        module.movie_hot.assert_not_called()

    def test_an_unknown_board_is_declined(self):
        """本源没有这个榜单时让出，而不是抛错。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)

        self.assertIsNone(
            module.discover_board(MediaSource.Douban, "no_such_board"))


class AsyncDiscoverBoardTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_async_board_routes_by_source_and_identifier(self):
        """异步取榜单同样按来源与标识路由。"""
        from app.modules.douban import DoubanModule

        async def top250(page=1, count=30):
            """异步固定榜单"""
            return ["媒体"]

        module = object.__new__(DoubanModule)
        module.async_movie_top250 = top250

        self.assertEqual(["媒体"],
                         await module.async_discover_board(
                             MediaSource.Douban, "movie_top250"))
        self.assertIsNone(
            await module.async_discover_board(MediaSource.TMDB, "movie_top250"))


if __name__ == "__main__":
    unittest.main()
