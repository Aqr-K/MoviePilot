import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock

from app.core.context import MediaInfo
from app.core.meta import MetaBase
from app.modules.douban import DoubanModule
from app.modules.themoviedb import TheMovieDbModule
from app.schemas.types import MediaType


class MediaRecognizeModulesTest(TestCase):
    def test_tmdb_cache_false_skips_cache_lookup(self):
        """cache=False 时应跳过缓存读取，但仍按正常流程查询 TMDB。"""
        module = TheMovieDbModule()
        meta = MetaBase("测试电影")
        meta.name = "测试电影"
        meta.type = MediaType.MOVIE
        module.cache = Mock()
        module.tmdb = Mock()
        module.tmdb.get_info.return_value = {
            "id": 100,
            "media_type": MediaType.MOVIE,
            "title": "测试电影",
            "genres": [],
        }
        module.category = Mock()
        module.category.get_movie_category.return_value = None

        result = module.recognize_media(meta=meta, tmdbid=100, cache=False)

        self.assertIsInstance(result, MediaInfo)
        self.assertEqual(result.tmdb_id, 100)
        module.cache.get.assert_not_called()
        module.cache.update.assert_called_once()

    def test_async_tmdb_cache_false_skips_cache_lookup(self):
        """异步 cache=False 时也应跳过缓存读取。"""
        module = TheMovieDbModule()
        meta = MetaBase("测试电影")
        meta.name = "测试电影"
        meta.type = MediaType.MOVIE
        module.cache = Mock()
        module.tmdb = Mock()

        async def _async_get_info(**kwargs):
            return {
                "id": 101,
                "media_type": MediaType.MOVIE,
                "title": "测试电影",
                "genres": [],
            }

        module.tmdb.async_get_info = _async_get_info
        module.category = Mock()
        module.category.get_movie_category.return_value = None

        result = asyncio.run(module.async_recognize_media(meta=meta, tmdbid=101, cache=False))

        self.assertIsInstance(result, MediaInfo)
        self.assertEqual(result.tmdb_id, 101)
        module.cache.get.assert_not_called()
        module.cache.update.assert_called_once()

    def test_tmdb_recognize_does_not_fallback_to_match_web(self):
        """TMDB API 搜索无结果时，不应再回退抓取 TMDB 网站搜索页。"""
        module = TheMovieDbModule()
        meta = MetaBase("No Match Movie")
        meta.name = "No Match Movie"
        meta.type = MediaType.MOVIE
        module.cache = Mock()
        module.tmdb = Mock()
        module.tmdb.match_web.side_effect = AssertionError("不应调用 TMDB 网站搜索")
        module._search_by_name = Mock(return_value=None)

        result = module.recognize_media(meta=meta, cache=False)

        self.assertIsNone(result)
        module._search_by_name.assert_called()
        module.tmdb.match_web.assert_not_called()

    def test_async_tmdb_recognize_does_not_fallback_to_match_web(self):
        """异步 TMDB API 搜索无结果时，不应再回退抓取 TMDB 网站搜索页。"""
        module = TheMovieDbModule()
        meta = MetaBase("No Match Movie")
        meta.name = "No Match Movie"
        meta.type = MediaType.MOVIE
        module.cache = Mock()
        module.tmdb = Mock()
        module.tmdb.async_match_web = AsyncMock(side_effect=AssertionError("不应调用 TMDB 网站搜索"))
        module._async_search_by_name = AsyncMock(return_value=None)

        result = asyncio.run(module.async_recognize_media(meta=meta, cache=False))

        self.assertIsNone(result)
        module._async_search_by_name.assert_called()
        module.tmdb.async_match_web.assert_not_called()

    def test_douban_prepare_search_names_deduplicates_simplified_name(self):
        """豆瓣候选名称应保留顺序，并去掉繁简转换后的重复项。"""
        meta = MetaBase("流浪地球")
        meta.cn_name = "流浪地球"
        meta.en_name = "The Wandering Earth"

        self.assertEqual(
            DoubanModule._prepare_search_names(meta),
            ["流浪地球", "The Wandering Earth"],
        )

    def test_douban_search_result_helper_preserves_season_title_rule(self):
        """豆瓣搜索结果 helper 应保留电视剧标题追加季号的旧逻辑。"""
        meta = MetaBase("测试剧")
        meta.name = "测试剧"
        meta.type = MediaType.TV
        meta.begin_season = 2
        items = [
            {
                "type_name": MediaType.TV.value,
                "target": {
                    "id": "200",
                    "title": "测试剧",
                    "type": "tv",
                    "year": "2024",
                },
            },
            {
                "type_name": MediaType.MOVIE.value,
                "target": {
                    "id": "201",
                    "title": "测试剧 电影版",
                    "type": "movie",
                    "year": "2024",
                },
            },
        ]

        result = DoubanModule._build_search_medias_result(meta, items)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].title, "测试剧 第二季")
        self.assertEqual(result[0].season, 2)
