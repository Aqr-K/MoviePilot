import socket

from app.helper import doh


def test_enable_doh_reuses_cached_host_resolution(monkeypatch):
    """
    同一 DoH 域名第二次解析应命中缓存，避免重复请求远端解析器。
    """
    query_calls = []
    resolved_hosts = []

    def fake_query(resolver: str, host: str) -> str:
        query_calls.append((resolver, host))
        return "203.0.113.7"

    def fake_getaddrinfo(host: str, *args, **kwargs):
        resolved_hosts.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (host, 0))]

    monkeypatch.setattr(doh.settings, "DOH_DOMAINS", "example.com")
    monkeypatch.setattr(doh.settings, "DOH_RESOLVERS", "resolver.test")
    monkeypatch.setattr(doh, "_doh_query", fake_query)
    monkeypatch.setattr(doh, "_orig_getaddrinfo", fake_getaddrinfo)

    original_getaddrinfo = socket.getaddrinfo
    with doh._doh_lock:
        doh._doh_cache.clear()

    try:
        doh.enable_doh(True)

        socket.getaddrinfo("example.com", None)
        socket.getaddrinfo("example.com", None)
    finally:
        socket.getaddrinfo = original_getaddrinfo
        with doh._doh_lock:
            doh._doh_cache.clear()

    assert query_calls == [("resolver.test", "example.com")]
    assert resolved_hosts == ["203.0.113.7", "203.0.113.7"]
