"""同步 HTTP 共享连接池的复用、隔离与生命周期用例。"""
import asyncio
import http.client
import threading
from types import SimpleNamespace

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict

from app.adapters.network import http as http_module
from app.adapters.network.http import RequestUtils


class _SendRecord:
    """记录一次适配器发送调用的适配器身份与传输参数。"""

    def __init__(self, adapter, request, kwargs):
        """
        :param adapter: 实际承载本次发送的 HTTPAdapter 实例
        :param request: 已准备好的 PreparedRequest
        :param kwargs: 适配器收到的传输参数
        """
        self.adapter = adapter
        self.request = request
        self.kwargs = kwargs

    @property
    def cookie_header(self):
        """返回本次请求携带的 Cookie 头，未携带时为 None。"""
        return self.request.headers.get("Cookie")


def _build_response(request, set_cookies=()):
    """
    构造不触碰套接字的响应对象，可携带 Set-Cookie 头。

    :param request: 已准备好的 PreparedRequest
    :param set_cookies: 响应要下发的 Set-Cookie 值列表
    :return: requests.Response 实例
    """
    response = requests.Response()
    response.status_code = 200
    response.reason = "OK"
    response.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
    response.url = request.url
    response.request = request
    response._content = b"{}"
    message = http.client.HTTPMessage()
    for cookie in set_cookies:
        message.add_header("Set-Cookie", cookie)
    response.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=message))
    extract_cookies_to_jar(response.cookies, request, response.raw)
    return response


def _patch_adapter_send(monkeypatch, set_cookies=(), side_effects=None):
    """
    拦截适配器发送环节，记录调用并返回构造响应。

    :param monkeypatch: pytest monkeypatch 夹具
    :param set_cookies: 首次响应下发的 Set-Cookie 值列表
    :param side_effects: 按调用顺序抛出的异常序列，None 表示正常响应
    :return: 记录列表，元素为 _SendRecord
    """
    records = []
    effects = list(side_effects or [])

    def fake_send(self, request, **kwargs):
        records.append(_SendRecord(self, request, kwargs))
        if effects:
            effect = effects.pop(0)
            if isinstance(effect, Exception):
                raise effect
        cookies = set_cookies if len(records) == 1 else ()
        return _build_response(request, cookies)

    monkeypatch.setattr(HTTPAdapter, "send", fake_send)
    return records


def test_sessionless_requests_share_one_connection_pool(monkeypatch):
    """未显式传 session 的请求应复用同一个 HTTPAdapter，从而复用 TCP/TLS 连接池。"""
    records = _patch_adapter_send(monkeypatch)

    RequestUtils().get_res("https://pool.example/first")
    RequestUtils().get_res("https://pool.example/second")

    assert len(records) == 2
    assert records[0].adapter is records[1].adapter


def test_shared_pool_does_not_leak_set_cookie_across_requests(monkeypatch):
    """上一次响应下发的 Set-Cookie 不得被带入后续请求。"""
    records = _patch_adapter_send(monkeypatch, set_cookies=["sid=leaked; Path=/"])

    request_utils = RequestUtils()
    request_utils.get_res("https://cookie.example/login")
    request_utils.get_res("https://cookie.example/profile")
    RequestUtils().get_res("https://other.example/profile")

    assert len(records) == 3
    assert records[1].cookie_header is None
    assert records[2].cookie_header is None


def test_instance_cookies_still_sent_on_shared_pool(monkeypatch):
    """实例级 cookies 仍需逐请求生效，且不受共享连接池影响。"""
    records = _patch_adapter_send(monkeypatch, set_cookies=["sid=leaked; Path=/"])

    RequestUtils(cookies="token=abc").get_res("https://cookie.example/one")
    RequestUtils().get_res("https://cookie.example/two")

    assert records[0].cookie_header == "token=abc"
    assert records[1].cookie_header is None


def test_different_proxy_configs_do_not_share_pool(monkeypatch):
    """不同代理配置必须落在不同的共享连接池上，相同代理配置则复用同一个。"""
    records = _patch_adapter_send(monkeypatch)
    proxy_a = {"http": "http://proxy-a:7890", "https": "http://proxy-a:7890"}
    proxy_b = {"http": "http://proxy-b:7890", "https": "http://proxy-b:7890"}

    RequestUtils(proxies=proxy_a).get_res("https://proxy.example/one")
    RequestUtils(proxies=dict(proxy_a)).get_res("https://proxy.example/two")
    RequestUtils(proxies=proxy_b).get_res("https://proxy.example/three")
    RequestUtils().get_res("https://proxy.example/four")

    assert records[0].adapter is records[1].adapter
    assert records[2].adapter is not records[0].adapter
    assert records[3].adapter is not records[0].adapter
    assert records[3].adapter is not records[2].adapter


def test_explicit_session_bypasses_shared_pool(monkeypatch):
    """显式传入 session 时应继续使用该 session 自己的适配器，不占用共享连接池。"""
    records = _patch_adapter_send(monkeypatch)
    http_module._close_shared_sync_adapters()
    explicit_session = requests.Session()

    RequestUtils(session=explicit_session).get_res("https://explicit.example/one")

    assert len(records) == 1
    assert records[0].adapter is explicit_session.get_adapter("https://explicit.example/one")
    assert not http_module._shared_sync_adapters


def test_per_request_transport_options_reach_adapter(monkeypatch):
    """逐请求的 verify、timeout、proxies 必须原样送达适配器，不被共享池默认值覆盖。"""
    records = _patch_adapter_send(monkeypatch)
    proxies = {"https": "http://proxy-c:7890"}

    RequestUtils(timeout=20).get_res(
        "https://options.example/data",
        verify="/tmp/custom-ca.pem",
        timeout=3,
        proxies=proxies,
    )

    assert records[0].kwargs["verify"] == "/tmp/custom-ca.pem"
    assert records[0].kwargs["timeout"] == 3
    assert records[0].kwargs["proxies"]["https"] == "http://proxy-c:7890"


def test_pooled_idempotent_request_retries_stale_connection(monkeypatch):
    """共享连接池取到失效 keep-alive 连接时，幂等请求应重试一次。"""
    records = _patch_adapter_send(
        monkeypatch,
        side_effects=[requests.exceptions.ConnectionError("Connection aborted")],
    )

    response = RequestUtils().get_res("https://stale.example/data")

    assert response is not None
    assert response.status_code == 200
    assert len(records) == 2


def test_pooled_non_idempotent_request_is_not_retried(monkeypatch):
    """非幂等请求连接异常时不得自动重试，避免重复提交副作用。"""
    records = _patch_adapter_send(
        monkeypatch,
        side_effects=[requests.exceptions.ConnectionError("Connection aborted")],
    )

    response = RequestUtils().post_res("https://stale.example/data", data={"a": 1})

    assert response is None
    assert len(records) == 1


def test_pooled_connect_timeout_is_not_retried(monkeypatch):
    """连接超时不属于连接池失效特征，不应重试放大等待时间。"""
    records = _patch_adapter_send(
        monkeypatch,
        side_effects=[requests.exceptions.ConnectTimeout("connect timeout")],
    )

    response = RequestUtils().get_res("https://timeout.example/data")

    assert response is None
    assert len(records) == 1


def test_pooled_retry_failure_raises_when_requested(monkeypatch):
    """开启 raise_exception 后，重试仍失败应抛出重试阶段的异常。"""
    retry_error = requests.exceptions.ConnectionError("still broken")
    _patch_adapter_send(
        monkeypatch,
        side_effects=[
            requests.exceptions.ConnectionError("Connection aborted"),
            retry_error,
        ],
    )

    with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
        RequestUtils().get_res("https://stale.example/data", raise_exception=True)

    assert excinfo.value is retry_error


def test_shared_adapter_pool_limits_match_async_side():
    """共享同步适配器的连接池上限应与异步侧保持一致。"""
    http_module._close_shared_sync_adapters()

    adapter = http_module._get_shared_sync_adapter(None)

    assert adapter._pool_connections == http_module._DEFAULT_SYNC_POOL_CONNECTIONS
    assert adapter._pool_maxsize == http_module._DEFAULT_MAX_CONNECTIONS


def test_close_shared_sync_adapters_releases_pools():
    """关闭共享同步连接池后注册表应清空，后续请求重新建池。"""
    http_module._close_shared_sync_adapters()
    adapter = http_module._get_shared_sync_adapter(None)
    assert http_module._shared_sync_adapters

    http_module._close_shared_sync_adapters()

    assert not http_module._shared_sync_adapters
    assert http_module._get_shared_sync_adapter(None) is not adapter


def test_async_shutdown_hook_also_releases_sync_pools():
    """应用关停钩子应同时释放同步共享连接池，避免连接泄漏。"""
    http_module._close_shared_sync_adapters()
    http_module._get_shared_sync_adapter(None)
    assert http_module._shared_sync_adapters

    asyncio.run(http_module.aclose_shared_async_transports())

    assert not http_module._shared_sync_adapters


def test_shared_sync_adapters_evict_least_recently_used():
    """共享同步适配器数量超过上限时应按 LRU 淘汰，防止无界增长。"""
    http_module._close_shared_sync_adapters()
    limit = http_module._MAX_SHARED_SYNC_ADAPTERS

    first = http_module._get_shared_sync_adapter({"https": "http://proxy-0:7890"})
    for index in range(1, limit + 1):
        http_module._get_shared_sync_adapter({"https": f"http://proxy-{index}:7890"})

    assert len(http_module._shared_sync_adapters) == limit
    assert http_module._get_shared_sync_adapter({"https": "http://proxy-0:7890"}) is not first

    http_module._close_shared_sync_adapters()


def test_concurrent_first_use_creates_single_shared_adapter():
    """多线程首次并发取用同一配置时只能创建一个共享适配器。"""
    http_module._close_shared_sync_adapters()
    barrier = threading.Barrier(16)
    adapters = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        adapter = http_module._get_shared_sync_adapter({"https": "http://race:7890"})
        with lock:
            adapters.append(adapter)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(adapters) == 16
    assert len({id(adapter) for adapter in adapters}) == 1

    http_module._close_shared_sync_adapters()
