from app.runtime.cache import cached
from app.runtime.config import settings
from ..tmdb import TMDb

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


class Discover(TMDb):
    _urls = {
        "movies": "/discover/movie",
        "tv": "/discover/tv"
    }

    # 缓存键含 genre/sort/page/rating/date 等多个筛选维度的组合，maxsize 需覆盖
    # 常见的组合数量（对齐 settings.CONF.tmdb 低配档的量级），否则翻页或换筛选
    # 条件会互相挤出缓存。call_cached=False 让请求绕过 TMDB 响应层的共享缓存，
    # 使筛选条件缓存过期后总能拿到实时发现结果，与 trending.py 的策略一致，保留不变。
    @cached(maxsize=256, ttl=43200, empty_ttl=settings.EMPTY_RESULT_CACHE_TTL)
    def discover_movies(self, params_tuple):
        """
        Discover movies by different types of data like average rating, number of votes, genres and certifications.
        :param params_tuple: dict
        :return:
        """
        params = dict(params_tuple)
        return self._request_obj(self._urls["movies"], urlencode(params), key="results", call_cached=False)

    @cached(maxsize=256, ttl=43200, empty_ttl=settings.EMPTY_RESULT_CACHE_TTL)
    def discover_tv_shows(self, params_tuple):
        """
        Discover TV shows by different types of data like average rating, number of votes, genres,
        the network they aired on and air dates.
        :param params_tuple: dict
        :return:
        """
        return self._request_obj(self._urls["tv"], urlencode(params_tuple), key="results", call_cached=False)

    @cached(maxsize=256, ttl=43200, empty_ttl=settings.EMPTY_RESULT_CACHE_TTL)
    async def async_discover_movies(self, params_tuple):
        """
        Discover movies by different types of data like average rating, number of votes, genres and certifications.（异步版本）
        :param params_tuple: dict
        :return:
        """
        params = dict(params_tuple)
        return await self._async_request_obj(self._urls["movies"], urlencode(params), key="results", call_cached=False)

    @cached(maxsize=256, ttl=43200, empty_ttl=settings.EMPTY_RESULT_CACHE_TTL)
    async def async_discover_tv_shows(self, params_tuple):
        """
        Discover TV shows by different types of data like average rating, number of votes, genres,
        the network they aired on and air dates.（异步版本）
        :param params_tuple: dict
        :return:
        """
        return await self._async_request_obj(self._urls["tv"], urlencode(params_tuple), key="results",
                                             call_cached=False)
