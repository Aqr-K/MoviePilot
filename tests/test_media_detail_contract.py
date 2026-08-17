"""媒体详情的统一契约。

五个源各占一套方法名，而且这批的差异比人物那两批更大——连 ID 的参数名和类型都不同：

    tmdb      (tmdbid: int, mtype, season)      需要类型与季
    douban    (doubanid: str, mtype, raise_exception)  ID 是字符串，且带限流开关
    bangumi   (bangumiid: int)
    anilist   (anilist_id: int)
    tvdb      (tvdbid: int)                     只有同步版

契约把这些收进 media_detail(source, media_id, mtype, season, raise_exception)：ID 统一
叫 media_id，各源自己转成本源要的类型与参数名；不需要的参数在契约实现里就地丢弃。

raise_exception 的缺省值以 chain 门面为准（False）。模块方法自己的缺省是 True，若照搬
会把「限流即抛错」变成默认行为，是行为变更而非归一。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource, MediaType


class MediaDetailContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_themoviedb_converts_id_and_passes_type_and_season(self):
        """TMDB 需要类型与季，ID 转为整型按本源参数名传下去。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_info = Mock(return_value={"id": 1})

        result = module.media_detail(MediaSource.TMDB, "1",
                                     mtype=MediaType.MOVIE, season=2)

        self.assertEqual({"id": 1}, result)
        module.tmdb_info.assert_called_once_with(
            tmdbid=1, mtype=MediaType.MOVIE, season=2)
        self.assertIsNone(module.media_detail(MediaSource.Douban, "1"))

    def test_douban_keeps_the_id_as_text_and_forwards_the_rate_limit_flag(self):
        """豆瓣 ID 是字符串，限流开关按调用方给的值传下去。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_info = Mock(return_value={"id": "d1"})

        result = module.media_detail(MediaSource.Douban, "d1",
                                     mtype=MediaType.TV, raise_exception=True)

        self.assertEqual({"id": "d1"}, result)
        module.douban_info.assert_called_once_with(
            doubanid="d1", mtype=MediaType.TV, raise_exception=True)
        self.assertIsNone(module.media_detail(MediaSource.TMDB, "d1"))

    def test_douban_does_not_raise_by_default(self):
        """缺省不抛限流异常——以 chain 门面的缺省为准。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_info = Mock(return_value={})

        module.media_detail(MediaSource.Douban, "d1")

        self.assertFalse(module.douban_info.call_args.kwargs["raise_exception"])

    def test_bangumi_takes_only_the_id(self):
        """Bangumi 只认 ID，多余参数不向下传。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_info = Mock(return_value={"id": 9})

        result = module.media_detail(MediaSource.Bangumi, "9",
                                     mtype=MediaType.TV, season=3)

        self.assertEqual({"id": 9}, result)
        module.bangumi_info.assert_called_once_with(bangumiid=9)

    def test_anilist_takes_only_the_id(self):
        """AniList 只认 ID，且参数名与别家不同。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_info = Mock(return_value={"id": 5})

        result = module.media_detail(MediaSource.AniList, "5")

        self.assertEqual({"id": 5}, result)
        module.anilist_info.assert_called_once_with(anilist_id=5)

    def test_thetvdb_takes_only_the_id(self):
        """TheTvDb 只认 ID。"""
        from app.modules.thetvdb import TheTvDbModule

        module = object.__new__(TheTvDbModule)
        module.tvdb_info = Mock(return_value={"id": 7})

        result = module.media_detail(MediaSource.TVDB, "7")

        self.assertEqual({"id": 7}, result)
        module.tvdb_info.assert_called_once_with(tvdbid=7)
        self.assertIsNone(module.media_detail(MediaSource.TMDB, "7"))

    def test_a_malformed_id_yields_nothing_instead_of_raising(self):
        """ID 无法转成本源要的类型时让出，不把 ValueError 抛进分发链。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_info = Mock()

        self.assertIsNone(module.media_detail(MediaSource.Bangumi, "not-a-number"))
        module.bangumi_info.assert_not_called()


class AsyncMediaDetailContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_async_contract_routes_by_source(self):
        """异步契约同样按来源自认领。"""
        from app.modules.bangumi import BangumiModule

        async def info(bangumiid=None):
            """异步媒体详情"""
            return {"id": bangumiid}

        module = object.__new__(BangumiModule)
        module.async_bangumi_info = info

        self.assertEqual({"id": 9},
                         await module.async_media_detail(MediaSource.Bangumi, "9"))
        self.assertIsNone(await module.async_media_detail(MediaSource.TMDB, "9"))

    async def test_a_source_without_an_async_variant_still_answers(self):
        """TheTvDb 没有异步实现，契约仍需应答——同步方法切线程池。"""
        from app.modules.thetvdb import TheTvDbModule

        module = object.__new__(TheTvDbModule)
        module.tvdb_info = Mock(return_value={"id": 7})

        result = await module.async_media_detail(MediaSource.TVDB, "7")

        self.assertEqual({"id": 7}, result)


if __name__ == "__main__":
    unittest.main()
