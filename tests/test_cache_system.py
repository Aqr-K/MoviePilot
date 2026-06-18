import asyncio

from app.core.cache import AsyncFileBackend, FileBackend, MemoryBackend
from app.core.config import settings
from app.helper.redis import AsyncRedisHelper, RedisHelper


def test_file_backend_items_keep_relative_keys_and_bytes(tmp_path):
    """
    文件缓存遍历应返回可继续删除的相对 key，并保持二进制内容不变。
    """
    cache = FileBackend(base=tmp_path)
    cache.set("nested/poster.jpg", b"\xff\xd8image", region="images")

    items = list(cache.items(region="images"))

    assert items == [("nested/poster.jpg", b"\xff\xd8image")]
    assert cache.popitem(region="images") == ("nested/poster.jpg", b"\xff\xd8image")
    assert not cache.exists("nested/poster.jpg", region="images")


def test_file_backend_delete_missing_key_is_noop(tmp_path):
    """
    删除不存在的文件缓存 key 应保持幂等，不向调用方抛出文件系统异常。
    """
    cache = FileBackend(base=tmp_path)

    cache.delete("missing", region="default")

    assert not cache.exists("missing", region="default")


def test_memory_backend_delete_missing_key_is_noop():
    """
    内存缓存后端 delete 与其他后端保持一致，不存在时直接返回。
    """
    cache = MemoryBackend()

    cache.delete("missing", region="missing_delete")

    assert not cache.exists("missing", region="missing_delete")


def test_redis_original_key_decodes_quoted_key():
    """
    Redis items 返回的 key 应还原为原始缓存 key，确保带特殊字符的 key 可继续删除。
    """
    redis_key = b"region:DEFAULT:key:nested/poster%20one.jpg"

    assert RedisHelper._RedisHelper__get_original_key(redis_key) == "nested/poster one.jpg"


def test_redis_helper_uses_blocking_pool_settings(monkeypatch):
    """
    Redis 同步客户端应使用阻塞连接池，避免并发峰值直接耗尽 Redis 连接数。
    """
    calls = {}

    class FakeClient:
        """模拟同步 Redis 客户端。"""

        def __init__(self, connection_pool):
            self.connection_pool = connection_pool
            self.config_calls = []
            self.closed = False

        def ping(self):
            """模拟 Redis ping。"""
            calls["ping"] = True

        def config_set(self, key, value):
            """记录 Redis 配置写入。"""
            self.config_calls.append((key, value))

        def close(self):
            """标记客户端已关闭。"""
            self.closed = True

    def fake_from_url(url, **kwargs):
        """记录连接池构造参数。"""
        calls["pool"] = {"url": url, **kwargs}
        return "pool"

    monkeypatch.setattr(settings, "CACHE_BACKEND_URL", "redis://cache:6379/2")
    monkeypatch.setattr(settings, "CACHE_REDIS_MAX_CONNECTIONS", 7)
    monkeypatch.setattr(settings, "CACHE_REDIS_POOL_TIMEOUT", 3)
    monkeypatch.setattr("app.helper.redis.redis.BlockingConnectionPool.from_url", fake_from_url)
    monkeypatch.setattr("app.helper.redis.redis.Redis", FakeClient)

    helper = RedisHelper()
    helper.close()
    helper._connect()

    assert calls["pool"]["url"] == "redis://cache:6379/2"
    assert calls["pool"]["max_connections"] == 7
    assert calls["pool"]["timeout"] == 3
    assert calls["pool"]["decode_responses"] is False
    assert calls["ping"] is True
    assert ("maxmemory-policy", "allkeys-lru") in helper.client.config_calls

    helper.close()


def test_async_redis_helper_uses_blocking_pool_settings(monkeypatch):
    """
    Redis 异步客户端应使用阻塞连接池，避免高并发缓存读取立刻抛出连接耗尽错误。
    """
    calls = {}

    class FakeAsyncClient:
        """模拟异步 Redis 客户端。"""

        def __init__(self, connection_pool):
            self.connection_pool = connection_pool
            self.config_calls = []
            self.closed = False

        async def ping(self):
            """模拟 Redis ping。"""
            calls["ping"] = True

        async def config_set(self, key, value):
            """记录 Redis 配置写入。"""
            self.config_calls.append((key, value))

        async def close(self):
            """标记客户端已关闭。"""
            self.closed = True

    def fake_from_url(url, **kwargs):
        """记录连接池构造参数。"""
        calls["pool"] = {"url": url, **kwargs}
        return "async_pool"

    async def run_connect():
        helper = AsyncRedisHelper()
        await helper.close()
        await helper._connect()
        config_calls = list(helper.client.config_calls)
        await helper.close()
        return config_calls

    monkeypatch.setattr(settings, "CACHE_BACKEND_URL", "redis://cache:6379/3")
    monkeypatch.setattr(settings, "CACHE_REDIS_MAX_CONNECTIONS", 9)
    monkeypatch.setattr(settings, "CACHE_REDIS_POOL_TIMEOUT", 4)
    monkeypatch.setattr("app.helper.redis.AsyncBlockingConnectionPool.from_url", fake_from_url)
    monkeypatch.setattr("app.helper.redis.Redis", FakeAsyncClient)

    config_calls = asyncio.run(run_connect())

    assert calls["pool"]["url"] == "redis://cache:6379/3"
    assert calls["pool"]["max_connections"] == 9
    assert calls["pool"]["timeout"] == 4
    assert calls["pool"]["decode_responses"] is False
    assert calls["ping"] is True
    assert ("maxmemory-policy", "allkeys-lru") in config_calls


def test_redis_helpers_watch_pool_settings():
    """
    Redis 连接池配置变化应触发客户端重建。
    """
    assert "CACHE_REDIS_MAX_CONNECTIONS" in RedisHelper.CONFIG_WATCH
    assert "CACHE_REDIS_POOL_TIMEOUT" in RedisHelper.CONFIG_WATCH
    assert "CACHE_REDIS_MAX_CONNECTIONS" in AsyncRedisHelper.CONFIG_WATCH
    assert "CACHE_REDIS_POOL_TIMEOUT" in AsyncRedisHelper.CONFIG_WATCH


def test_async_file_backend_missing_region_has_no_items(tmp_path):
    """
    异步文件缓存缺失区域时应返回空迭代，而不是伪造空 key。
    """

    async def collect_items():
        cache = AsyncFileBackend(base=tmp_path)
        return [item async for item in cache.items(region="missing")]

    assert asyncio.run(collect_items()) == []


def test_async_file_backend_items_keep_relative_keys_and_bytes(tmp_path):
    """
    异步文件缓存遍历应与同步文件缓存保持相同 key 和二进制语义。
    """

    async def collect_items():
        cache = AsyncFileBackend(base=tmp_path)
        await cache.set("nested/poster.jpg", b"\xff\xd8image", region="images")
        items = [item async for item in cache.items(region="images")]
        popped = await cache.popitem(region="images")
        exists = await cache.exists("nested/poster.jpg", region="images")
        return items, popped, exists

    items, popped, exists = asyncio.run(collect_items())

    assert items == [("nested/poster.jpg", b"\xff\xd8image")]
    assert popped == ("nested/poster.jpg", b"\xff\xd8image")
    assert not exists


def test_file_backend_items_skip_directories(tmp_path):
    """
    文件缓存遍历应递归读取有效缓存文件，不把目录当成缓存项。
    """
    cache = FileBackend(base=tmp_path)
    cache.set("nested/value", b"value", region="region")
    (tmp_path / "region" / "empty_dir").mkdir()

    assert list(cache.items(region="region")) == [("nested/value", b"value")]
