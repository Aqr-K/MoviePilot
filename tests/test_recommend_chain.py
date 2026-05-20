import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, patch

from app.chain.recommend import RecommendChain
from app.core.cache import TTLCache


class RecommendChainTest(TestCase):
    def tearDown(self):
        """
        清理推荐缓存，避免缓存装饰器状态影响其他用例。
        """
        RecommendChain.tmdb_trending.cache_clear()
        asyncio.run(RecommendChain.async_tmdb_trending.cache_clear())
        TTLCache(region=RecommendChain.recommend_cache_region).clear()

    def test_tmdb_trending_does_not_cache_empty_result(self):
        """
        TMDB流行趋势返回空列表时不应缓存，避免一次接口异常后长时间固定为空。
        """
        chain = RecommendChain()
        with patch("app.chain.recommend.TmdbChain") as tmdb_chain:
            tmdb_chain.return_value.tmdb_trending.side_effect = [[], []]

            self.assertEqual(chain.tmdb_trending(page=1), [])
            self.assertEqual(chain.tmdb_trending(page=1), [])

        self.assertEqual(tmdb_chain.return_value.tmdb_trending.call_count, 2)

    def test_async_tmdb_trending_does_not_cache_empty_result(self):
        """
        异步TMDB流行趋势返回空列表时也不应缓存。
        """
        chain = RecommendChain()
        with patch("app.chain.recommend.TmdbChain") as tmdb_chain:
            tmdb_chain.return_value.async_run_module = AsyncMock(side_effect=[[], []])

            self.assertEqual(asyncio.run(chain.async_tmdb_trending(page=1)), [])
            self.assertEqual(asyncio.run(chain.async_tmdb_trending(page=1)), [])

        self.assertEqual(tmdb_chain.return_value.async_run_module.call_count, 2)
