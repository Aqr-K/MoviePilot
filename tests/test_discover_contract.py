"""条件发现的统一契约。

四个源各占一套方法名，筛选条件却各不相同：

    tmdb      (mtype, sort_by, with_genres, with_original_language, with_keywords,
               with_watch_providers, vote_average, vote_count, release_date, page)
    douban    (mtype, sort, tags, page, count)
    bangumi   (**kwargs)
    anilist   (**kwargs)

契约只归一「方法名」这一层：discover(source, **criteria) 把条件原样转给本源方法。
调用方从「要知道调哪个方法名」变成「要知道传哪个 source」，新增源不必再往 chain 里
加方法。

各源支持哪些筛选条件仍由各源自己的签名约束——契约不代为校验，也不代填默认值：
tmdb 那九个必填条件缺一就该报错，让它在契约层被悄悄补上反而会掩盖调用方的疏漏。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource, MediaType


class DiscoverContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_themoviedb_forwards_every_criterion(self):
        """TMDB 的筛选条件原样转给本源方法。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_discover = Mock(return_value=["媒体"])

        result = module.discover(MediaSource.TMDB, mtype=MediaType.MOVIE,
                                 sort_by="popularity.desc", with_genres="28", page=2)

        self.assertEqual(["媒体"], result)
        module.tmdb_discover.assert_called_once_with(
            mtype=MediaType.MOVIE, sort_by="popularity.desc",
            with_genres="28", page=2)
        self.assertIsNone(module.discover(MediaSource.Douban))

    def test_douban_forwards_its_own_criteria(self):
        """豆瓣的筛选条件与 TMDB 不同名，同样原样转发。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_discover = Mock(return_value=["媒体"])

        result = module.discover(MediaSource.Douban, mtype=MediaType.TV,
                                 sort="R", tags="喜剧", page=1, count=30)

        self.assertEqual(["媒体"], result)
        module.douban_discover.assert_called_once_with(
            mtype=MediaType.TV, sort="R", tags="喜剧", page=1, count=30)
        self.assertIsNone(module.discover(MediaSource.TMDB))

    def test_bangumi_forwards_arbitrary_criteria(self):
        """Bangumi 本就接受任意条件，契约不额外约束。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_discover = Mock(return_value=["媒体"])

        result = module.discover(MediaSource.Bangumi, type=2, page=1)

        self.assertEqual(["媒体"], result)
        module.bangumi_discover.assert_called_once_with(type=2, page=1)
        self.assertIsNone(module.discover(MediaSource.AniList))

    def test_anilist_forwards_arbitrary_criteria(self):
        """AniList 同样接受任意条件。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_discover = Mock(return_value=["媒体"])

        result = module.discover(MediaSource.AniList, season="WINTER")

        self.assertEqual(["媒体"], result)
        module.anilist_discover.assert_called_once_with(season="WINTER")
        self.assertIsNone(module.discover(MediaSource.Bangumi))

    def test_the_contract_does_not_fill_in_missing_criteria(self):
        """契约不代填默认值——缺条件该由本源方法报错，不能被悄悄补上。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_discover = Mock(return_value=[])

        module.discover(MediaSource.Douban, mtype=MediaType.TV)

        self.assertEqual({"mtype": MediaType.TV},
                         module.douban_discover.call_args.kwargs)


class AsyncDiscoverContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_async_contract_routes_by_source(self):
        """异步契约同样按来源自认领。"""
        from app.modules.bangumi import BangumiModule

        async def discover(**criteria):
            """异步条件发现"""
            return ["媒体"]

        module = object.__new__(BangumiModule)
        module.async_bangumi_discover = discover

        self.assertEqual(["媒体"],
                         await module.async_discover(MediaSource.Bangumi, type=2))
        self.assertIsNone(await module.async_discover(MediaSource.TMDB))


if __name__ == "__main__":
    unittest.main()
