"""按名称匹配媒体的统一契约。

两个源各占一套方法名，签名并不整齐：

    tmdb    match_tmdbinfo(name, mtype, year, season)                    无 imdbid，无限流开关
    douban  match_doubaninfo(name, imdbid, mtype, year, season, raise_exception)  ID 可选，带限流开关

契约把这些收进 match_media(source, name, mtype, year, season, imdbid, raise_exception)：
不需要的参数（TMDB 不认 imdbid 与 raise_exception）在契约实现里就地丢弃，不传给原方法，
否则原方法会因不认得的关键字参数抛 TypeError。

raise_exception 的缺省值以 chain 门面为准（False）。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource, MediaType


class MatchMediaContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_themoviedb_ignores_imdbid_and_raise_exception(self):
        """TMDB 不认 imdbid 与 raise_exception，契约实现就地丢弃，不传给原方法。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.match_tmdbinfo = Mock(return_value={"id": 1})

        result = module.match_media(MediaSource.TMDB, name="测试电影",
                                    mtype=MediaType.MOVIE, year="2024", season=2,
                                    imdbid="tt123", raise_exception=True)

        self.assertEqual({"id": 1}, result)
        module.match_tmdbinfo.assert_called_once_with(
            name="测试电影", mtype=MediaType.MOVIE, year="2024", season=2)
        self.assertIsNone(module.match_media(MediaSource.Douban, name="测试电影"))

    def test_douban_forwards_imdbid_and_the_rate_limit_flag(self):
        """豆瓣认 imdbid 与限流开关，按调用方给的值传下去。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.match_doubaninfo = Mock(return_value={"id": "d1"})

        result = module.match_media(MediaSource.Douban, name="测试电影",
                                    mtype=MediaType.TV, year="2024", season=1,
                                    imdbid="tt123", raise_exception=True)

        self.assertEqual({"id": "d1"}, result)
        module.match_doubaninfo.assert_called_once_with(
            name="测试电影", imdbid="tt123", mtype=MediaType.TV,
            year="2024", season=1, raise_exception=True)
        self.assertIsNone(module.match_media(MediaSource.TMDB, name="测试电影"))

    def test_douban_does_not_raise_by_default(self):
        """缺省不抛限流异常——以 chain 门面的缺省为准。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.match_doubaninfo = Mock(return_value={})

        module.match_media(MediaSource.Douban, name="测试电影")

        self.assertFalse(module.match_doubaninfo.call_args.kwargs["raise_exception"])


class AsyncMatchMediaContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_async_contract_routes_by_source(self):
        """异步契约同样按来源自认领。"""
        from app.modules.themoviedb import TheMovieDbModule

        async def match(name=None, mtype=None, year=None, season=None):
            """异步匹配TMDB信息"""
            return {"id": name}

        module = object.__new__(TheMovieDbModule)
        module.async_match_tmdbinfo = match

        self.assertEqual({"id": "测试电影"},
                         await module.async_match_media(MediaSource.TMDB, name="测试电影"))
        self.assertIsNone(await module.async_match_media(MediaSource.Douban, name="测试电影"))

    async def test_douban_async_forwards_imdbid_and_the_rate_limit_flag(self):
        """豆瓣异步契约同样认 imdbid 与限流开关。"""
        from unittest.mock import AsyncMock

        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.async_match_doubaninfo = AsyncMock(return_value={"id": "d1"})

        result = await module.async_match_media(MediaSource.Douban, name="测试电影",
                                                 imdbid="tt123", raise_exception=True)

        self.assertEqual({"id": "d1"}, result)
        module.async_match_doubaninfo.assert_called_once_with(
            name="测试电影", imdbid="tt123", mtype=None, year=None, season=None,
            raise_exception=True)


if __name__ == "__main__":
    unittest.main()
