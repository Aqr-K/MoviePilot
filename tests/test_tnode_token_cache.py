"""tnode 爬虫 CSRF token 缓存的站点隔离测试。

@cached 装饰器构造缓存键时会剥离 self，__get_token 除 self 外没有其它参数，
缓存键因此退化为常量字符串，所有站点共用同一条 token 缓存。当前被
SingletonClass（按类只保留一个实例）掩盖而未触发，一旦出现多实例场景
（如按站点各自持有 TNodeSpider）即会互相覆盖对方的 token。
"""
from unittest.mock import Mock, patch

import pytest

from app.modules.indexer.spider.tnode import TNodeSpider


@pytest.fixture(autouse=True)
def _clear_token_cache():
    """用例前后清空 token 缓存区域，避免跨用例污染进程级缓存。"""
    TNodeSpider._TNodeSpider__get_token.cache_clear()
    yield
    TNodeSpider._TNodeSpider__get_token.cache_clear()


def _build_spider(domain: str) -> TNodeSpider:
    """绕过 SingletonClass 直接构造独立的 TNodeSpider 实例，模拟多站点并存场景。"""
    spider = TNodeSpider.__new__(TNodeSpider)
    spider._domain = domain
    spider._ua = "test-ua"
    spider._proxy = None
    spider._cookie = "cookie"
    spider._timeout = 15
    spider._name = domain
    return spider


def _fake_response(token: str) -> Mock:
    """构造带有指定 CSRF token 的伪响应对象。"""
    response = Mock()
    response.status_code = 200
    response.text = f'<meta name="x-csrf-token" content="{token}">'
    return response


def test_different_sites_do_not_share_csrf_token_cache():
    """两个不同站点各自获取到的 token 不能互相覆盖对方的缓存。"""
    site_a = _build_spider("https://site-a.example/")
    site_b = _build_spider("https://site-b.example/")

    responses = {
        "https://site-a.example/": _fake_response("token-a"),
        "https://site-b.example/": _fake_response("token-b"),
    }

    with patch("app.modules.indexer.spider.tnode.RequestUtils") as request_utils_cls:
        request_utils_cls.return_value.get_res.side_effect = (
            lambda url, **kwargs: responses[url]
        )

        token_a = site_a._TNodeSpider__get_token(site_a._domain)
        token_b = site_b._TNodeSpider__get_token(site_b._domain)

    assert token_a == "token-a"
    assert token_b == "token-b"


def test_same_site_repeated_call_hits_cache():
    """同一站点重复获取 token 应命中缓存，不重复发起请求。"""
    site_a = _build_spider("https://site-a.example/")
    response = _fake_response("token-a")

    with patch("app.modules.indexer.spider.tnode.RequestUtils") as request_utils_cls:
        request_utils_cls.return_value.get_res.return_value = response

        site_a._TNodeSpider__get_token(site_a._domain)
        site_a._TNodeSpider__get_token(site_a._domain)

        assert request_utils_cls.return_value.get_res.call_count == 1
