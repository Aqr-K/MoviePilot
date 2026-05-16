import asyncio
import importlib.util
import pickle
import sys
from contextlib import asynccontextmanager, contextmanager
from functools import wraps
from pathlib import Path
from threading import RLock
from types import ModuleType, SimpleNamespace
from unittest import TestCase


TMDB_MODULE_NAME = "app.modules.themoviedb.tmdbv3api.tmdb"
TMDB_FILE_PATH = Path(__file__).resolve().parents[1] / "app/modules/themoviedb/tmdbv3api/tmdb.py"


def _ensure_package(name: str) -> ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        module.__path__ = []
        sys.modules[name] = module
    return module


def _install_tmdb_test_stubs() -> None:
    for package_name in [
        "app",
        "app.core",
        "app.utils",
        "app.modules",
        "app.modules.themoviedb",
        "app.modules.themoviedb.tmdbv3api",
    ]:
        _ensure_package(package_name)

    cache_module = ModuleType("app.core.cache")

    def cached(*args, **kwargs):
        def decorator(func):
            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*wrapper_args, **wrapper_kwargs):
                    return await func(*wrapper_args, **wrapper_kwargs)

                return async_wrapper

            @wraps(func)
            def wrapper(*wrapper_args, **wrapper_kwargs):
                return func(*wrapper_args, **wrapper_kwargs)

            return wrapper

        return decorator

    @contextmanager
    def fresh(*args, **kwargs):
        yield

    @asynccontextmanager
    async def async_fresh(*args, **kwargs):
        yield

    cache_module.cached = cached
    cache_module.fresh = fresh
    cache_module.async_fresh = async_fresh
    sys.modules[cache_module.__name__] = cache_module

    config_module = ModuleType("app.core.config")
    config_module.settings = SimpleNamespace(
        TMDB_API_KEY="dummy-key",
        TMDB_LOCALE="en-US",
        PROXY=None,
        TMDB_API_DOMAIN="example.com",
        NORMAL_USER_AGENT="MoviePilot-Test-UA",
        CONF=SimpleNamespace(tmdb=8, meta=60),
    )
    sys.modules[config_module.__name__] = config_module

    http_module = ModuleType("app.utils.http")

    class RequestUtils:
        def __init__(self, *args, **kwargs):
            pass

        def get_res(self, *args, **kwargs):  # pragma: no cover - 测试中会替换
            raise NotImplementedError

        def post_res(self, *args, **kwargs):  # pragma: no cover - 测试中会替换
            raise NotImplementedError

    class AsyncRequestUtils:
        def __init__(self, *args, **kwargs):
            pass

        async def get_res(self, *args, **kwargs):  # pragma: no cover - 测试中会替换
            raise NotImplementedError

        async def post_res(self, *args, **kwargs):  # pragma: no cover - 测试中会替换
            raise NotImplementedError

    http_module.RequestUtils = RequestUtils
    http_module.AsyncRequestUtils = AsyncRequestUtils
    sys.modules[http_module.__name__] = http_module

    exceptions_module = ModuleType("app.modules.themoviedb.tmdbv3api.exceptions")

    class TMDbException(Exception):
        pass

    exceptions_module.TMDbException = TMDbException
    sys.modules[exceptions_module.__name__] = exceptions_module


def _load_tmdb_class():
    _install_tmdb_test_stubs()
    sys.modules.pop(TMDB_MODULE_NAME, None)
    spec = importlib.util.spec_from_file_location(TMDB_MODULE_NAME, TMDB_FILE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[TMDB_MODULE_NAME] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.TMDb


TMDb = _load_tmdb_class()


class _FakeResponse:
    def __init__(self, payload: dict, headers: dict):
        self._payload = payload
        self.headers = headers
        self._lock = RLock()

    def json(self):
        return self._payload


class TmdbResponseCacheTest(TestCase):
    def test_request_returns_pickleable_snapshot(self):
        tmdb = TMDb()
        response = _FakeResponse(
            payload={"id": 1, "page": 2},
            headers={"X-RateLimit-Remaining": "39", "X-RateLimit-Reset": "1234567890"},
        )
        tmdb._req.get_res = lambda *args, **kwargs: response

        result = TMDb.request.__wrapped__(tmdb, "GET", "https://example.com", None, None)

        self.assertTrue(result[TMDb._RESPONSE_SNAPSHOT_MARKER])
        self.assertEqual(result["json"], {"id": 1, "page": 2})
        self.assertEqual(result["headers"]["X-RateLimit-Remaining"], "39")
        pickle.dumps(result)

    def test_async_request_returns_pickleable_snapshot(self):
        tmdb = TMDb()
        response = _FakeResponse(
            payload={"id": 2, "page": 3},
            headers={"x-ratelimit-remaining": "38", "x-ratelimit-reset": "1234567891"},
        )

        async def _fake_get_res(*args, **kwargs):
            return response

        tmdb._async_req.get_res = _fake_get_res

        result = asyncio.run(
            TMDb.async_request.__wrapped__(tmdb, "GET", "https://example.com", None, None)
        )

        self.assertTrue(result[TMDb._RESPONSE_SNAPSHOT_MARKER])
        self.assertEqual(result["json"], {"id": 2, "page": 3})
        self.assertEqual(result["headers"]["x-ratelimit-remaining"], "38")
        pickle.dumps(result)

    def test_handle_headers_accepts_snapshot_headers(self):
        tmdb = TMDb()

        tmdb._handle_headers({"x-ratelimit-remaining": "7", "x-ratelimit-reset": "99"})

        self.assertEqual(tmdb._remaining, 7)
        self.assertEqual(tmdb._reset, 99)

    def test_get_response_json_returns_snapshot_copy(self):
        snapshot = {
            TMDb._RESPONSE_SNAPSHOT_MARKER: True,
            "headers": {},
            "json": {
                "results": [
                    {"id": 1, "media_type": "movie"},
                    {"id": 2, "media_type": "tv"},
                ]
            },
        }

        first_json = TMDb._get_response_json(snapshot)
        first_json["results"][0]["media_type"] = "电影"

        second_json = TMDb._get_response_json(snapshot)

        self.assertEqual(second_json["results"][0]["media_type"], "movie")
        self.assertIsNot(first_json, second_json)
        self.assertIsNot(first_json["results"][0], second_json["results"][0])

    def test_async_request_obj_returns_copied_key_from_snapshot(self):
        tmdb = TMDb()
        snapshot = {
            TMDb._RESPONSE_SNAPSHOT_MARKER: True,
            "headers": {"x-ratelimit-remaining": "39", "x-ratelimit-reset": "1234567890"},
            "json": {
                "page": 1,
                "results": [
                    {"id": 1, "media_type": "movie"},
                    {"id": 2, "media_type": "tv"},
                ],
            },
        }

        async def _fake_async_request(*args, **kwargs):
            return snapshot

        tmdb.async_request = _fake_async_request

        first_results = asyncio.run(tmdb._async_request_obj("/search/multi", key="results"))
        first_results[0]["media_type"] = "电影"

        second_results = asyncio.run(tmdb._async_request_obj("/search/multi", key="results"))

        self.assertEqual(second_results[0]["media_type"], "movie")
        self.assertIsNot(first_results, second_results)
        self.assertIsNot(first_results[0], second_results[0])
