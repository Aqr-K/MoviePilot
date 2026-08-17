"""相关推荐的统一契约。

四个源把同一能力拆成了十个方法名——tmdb_movie_recommend/tmdb_tv_recommend、
douban_movie_recommend/douban_tv_recommend、bangumi_recommend、
anilist_recommendations——电影/剧集的区分被编进方法名而不是参数：

    tmdb    movie: (tmdbid: int)   tv: (tmdbid: int)              —— 不分页
    douban  movie: (doubanid: str) tv: (doubanid: str)            —— 不分页
    bangumi        (bangumiid: int)                               —— 不分电影/剧集，也不分页
    anilist        (anilist_id: int, page=1, count=20)            —— 不分电影/剧集，支持分页

契约收进 media_recommend(source, media_id, mtype, page, count)：mtype 承载电影/剧集的
区分（TV 走剧集接口，其余按电影处理），ID 统一叫 media_id，各源自己转成本源要的类型；
不需要的参数（tmdb/douban/bangumi 的 page/count）在契约实现里就地丢弃，AniList 的
count 缺省时补本源默认值 20；转换失败的 ID 让出而不抛异常。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource, MediaType


class MediaRecommendContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_themoviedb_routes_movie_and_converts_id(self):
        """TMDB 电影分支：ID 转为整型，本源不支持分页。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_movie_recommend = Mock(return_value=["推荐电影"])
        module.tmdb_tv_recommend = Mock(return_value=["推荐剧集"])

        result = module.media_recommend(MediaSource.TMDB, "1", mtype=MediaType.MOVIE, page=2)

        self.assertEqual(["推荐电影"], result)
        module.tmdb_movie_recommend.assert_called_once_with(tmdbid=1)
        module.tmdb_tv_recommend.assert_not_called()
        self.assertIsNone(module.media_recommend(MediaSource.Douban, "1"))

    def test_themoviedb_routes_tv(self):
        """TMDB 剧集分支由 mtype=TV 触发。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_movie_recommend = Mock(return_value=["推荐电影"])
        module.tmdb_tv_recommend = Mock(return_value=["推荐剧集"])

        result = module.media_recommend(MediaSource.TMDB, "1", mtype=MediaType.TV)

        self.assertEqual(["推荐剧集"], result)
        module.tmdb_tv_recommend.assert_called_once_with(tmdbid=1)
        module.tmdb_movie_recommend.assert_not_called()

    def test_themoviedb_malformed_id_yields_nothing(self):
        """ID 无法转成本源要的类型时让出，不把 ValueError 抛进分发链。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_movie_recommend = Mock()
        module.tmdb_tv_recommend = Mock()

        self.assertIsNone(module.media_recommend(MediaSource.TMDB, "not-a-number"))
        module.tmdb_movie_recommend.assert_not_called()
        module.tmdb_tv_recommend.assert_not_called()

    def test_douban_routes_movie_and_keeps_id_as_text(self):
        """豆瓣电影分支：ID 保持字符串，本源不分页。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_movie_recommend = Mock(return_value=["推荐电影"])
        module.douban_tv_recommend = Mock(return_value=["推荐剧集"])

        result = module.media_recommend(MediaSource.Douban, "d1", mtype=MediaType.MOVIE, page=2)

        self.assertEqual(["推荐电影"], result)
        module.douban_movie_recommend.assert_called_once_with(doubanid="d1")
        module.douban_tv_recommend.assert_not_called()
        self.assertIsNone(module.media_recommend(MediaSource.TMDB, "d1"))

    def test_douban_routes_tv(self):
        """豆瓣剧集分支由 mtype=TV 触发。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_movie_recommend = Mock(return_value=["推荐电影"])
        module.douban_tv_recommend = Mock(return_value=["推荐剧集"])

        result = module.media_recommend(MediaSource.Douban, "d1", mtype=MediaType.TV)

        self.assertEqual(["推荐剧集"], result)
        module.douban_tv_recommend.assert_called_once_with(doubanid="d1")
        module.douban_movie_recommend.assert_not_called()

    def test_bangumi_does_not_split_by_type_or_page(self):
        """Bangumi 只有一套接口，不分电影/剧集也不分页，多余参数不下传。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_recommend = Mock(return_value=["推荐"])

        result = module.media_recommend(MediaSource.Bangumi, "9", mtype=MediaType.TV, page=5, count=10)

        self.assertEqual(["推荐"], result)
        module.bangumi_recommend.assert_called_once_with(bangumiid=9)
        self.assertIsNone(module.media_recommend(MediaSource.Douban, "9"))

    def test_bangumi_malformed_id_yields_nothing(self):
        """Bangumi 同样对非法 ID 让出而不抛异常。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_recommend = Mock()

        self.assertIsNone(module.media_recommend(MediaSource.Bangumi, "not-a-number"))
        module.bangumi_recommend.assert_not_called()

    def test_anilist_does_not_split_by_type_and_defaults_count(self):
        """AniList 不分电影/剧集，但支持分页；count 缺省时补本源默认值 20。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_recommendations = Mock(return_value=["推荐"])

        result = module.media_recommend(MediaSource.AniList, "5", mtype=MediaType.TV, page=2)

        self.assertEqual(["推荐"], result)
        module.anilist_recommendations.assert_called_once_with(anilist_id=5, page=2, count=20)
        self.assertIsNone(module.media_recommend(MediaSource.TMDB, "5"))

    def test_anilist_forwards_explicit_count(self):
        """AniList 显式传入 count 时原样下传，不被默认值覆盖。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_recommendations = Mock(return_value=["推荐"])

        module.media_recommend(MediaSource.AniList, "5", page=3, count=8)

        module.anilist_recommendations.assert_called_once_with(anilist_id=5, page=3, count=8)

    def test_anilist_malformed_id_yields_nothing(self):
        """AniList 同样对非法 ID 让出而不抛异常。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_recommendations = Mock()

        self.assertIsNone(module.media_recommend(MediaSource.AniList, "not-a-number"))
        module.anilist_recommendations.assert_not_called()


class AsyncMediaRecommendContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_themoviedb_async_routes_by_type(self):
        """TMDB 异步契约同样按 mtype 分流，并转换 ID。"""
        from app.modules.themoviedb import TheMovieDbModule

        async def movie_recommend(tmdbid=None):
            """异步推荐电影"""
            return ["推荐电影"]

        async def tv_recommend(tmdbid=None):
            """异步推荐剧集"""
            return ["推荐剧集"]

        module = object.__new__(TheMovieDbModule)
        module.async_tmdb_movie_recommend = movie_recommend
        module.async_tmdb_tv_recommend = tv_recommend

        result = await module.async_media_recommend(MediaSource.TMDB, "1", mtype=MediaType.TV)
        self.assertEqual(["推荐剧集"], result)
        self.assertIsNone(await module.async_media_recommend(MediaSource.Douban, "1"))

    async def test_douban_async_routes_by_type(self):
        """豆瓣异步契约同样按 mtype 分流。"""
        from app.modules.douban import DoubanModule

        async def movie_recommend(doubanid=None):
            """异步推荐电影"""
            return ["推荐电影"]

        module = object.__new__(DoubanModule)
        module.async_douban_movie_recommend = movie_recommend

        result = await module.async_media_recommend(MediaSource.Douban, "d1", mtype=MediaType.MOVIE)
        self.assertEqual(["推荐电影"], result)

    async def test_bangumi_async_ignores_type_and_page(self):
        """Bangumi 异步契约不分电影/剧集也不分页。"""
        from app.modules.bangumi import BangumiModule

        async def recommend_(bangumiid=None):
            """异步推荐"""
            return ["推荐"]

        module = object.__new__(BangumiModule)
        module.async_bangumi_recommend = recommend_

        result = await module.async_media_recommend(MediaSource.Bangumi, "9", mtype=MediaType.MOVIE, page=2)
        self.assertEqual(["推荐"], result)
        self.assertIsNone(await module.async_media_recommend(MediaSource.TMDB, "9"))

    async def test_anilist_async_defaults_count(self):
        """AniList 异步契约同样在 count 缺省时补 20。"""
        from app.modules.anilist import AniListModule

        async def recommendations(anilist_id=None, page=1, count=20):
            """异步推荐"""
            return ["推荐"]

        module = object.__new__(AniListModule)
        module.async_anilist_recommendations = recommendations

        result = await module.async_media_recommend(MediaSource.AniList, "5", page=1)
        self.assertEqual(["推荐"], result)
        self.assertIsNone(await module.async_media_recommend(MediaSource.TMDB, "5"))


if __name__ == "__main__":
    unittest.main()
