"""Plex 媒体库最近添加图片缓存的服务器隔离测试。

@cached 装饰器构造缓存键时会剥离 self，若被装饰方法除 self 外的参数不包含
服务器身份，配置多台 Plex 服务器且 library_key 相同时会互相返回对方的图片，
且持续整个 TTL 周期。
"""
from unittest.mock import Mock

import pytest

from app.modules.plex.plex import Plex


@pytest.fixture(autouse=True)
def _clear_library_images_cache():
    """用例前后清空图片缓存区域，避免跨用例污染进程级缓存。"""
    Plex._Plex__get_library_images.cache_clear()
    yield
    Plex._Plex__get_library_images.cache_clear()


def _build_plex(host: str, token: str, thumb: str) -> Plex:
    """构造绕过真实连接的 Plex 实例，用 mock 的 fetchItems 模拟服务器返回的最近添加条目。"""
    plex = Plex.__new__(Plex)
    plex._host = host
    plex._playhost = None
    plex._token = token
    plex._plex = Mock()
    plex._sync_libraries = []

    item = Mock()
    item.type = "movie"
    item.thumb = thumb
    item.parentThumb = None
    plex._plex.fetchItems.return_value = [item]

    library = Mock()
    library.key = "1"
    library.type = "movie"
    library.title = "Movies"
    library.locations = ["/data/movies"]
    plex._plex.library.sections.return_value = [library]
    plex.get_items_count = Mock(return_value=1)
    return plex


def test_same_library_key_on_two_plex_servers_does_not_share_images():
    """两台 library_key 相同的 Plex 服务器，图片缓存不能互相串味。"""
    server_a = _build_plex("http://server-a:32400/", "token-a", "/library/metadata/1/thumb/1")
    server_b = _build_plex("http://server-b:32400/", "token-b", "/library/metadata/2/thumb/1")

    images_a = server_a.get_librarys()[0].image_list
    images_b = server_b.get_librarys()[0].image_list

    assert images_a != images_b
    assert all("server-a" in url for url in images_a)
    assert all("server-b" in url for url in images_b)


def test_same_server_repeated_call_hits_cache():
    """同一台服务器重复查询同一媒体库应命中缓存，不重新调用 fetchItems。"""
    server = _build_plex("http://server-a:32400/", "token-a", "/library/metadata/1/thumb/1")

    server.get_librarys()
    server.get_librarys()

    assert server._plex.fetchItems.call_count == 1
