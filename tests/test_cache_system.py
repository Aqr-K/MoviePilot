import asyncio

from app.core.cache import AsyncFileBackend, FileBackend, MemoryBackend
from app.helper.redis import RedisHelper


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
