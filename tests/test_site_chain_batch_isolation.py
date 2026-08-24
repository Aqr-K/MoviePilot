"""
覆盖 SiteChain 批量处理循环的异常隔离行为：单个站点处理失败不应中断其余站点。
"""
from types import SimpleNamespace
from unittest.mock import Mock

from app.application.orchestration import site as site_module
from app.application.orchestration.site import SiteChain


def _site(site_id: int, name: str) -> dict:
    """构造一个最小可用的站点索引配置字典。"""
    return {
        "id": site_id,
        "name": name,
        "domain": f"{name}.example.com",
        "is_active": True,
    }


def test_refresh_userdatas_continues_after_one_site_raises(monkeypatch) -> None:
    """
    批量刷新站点用户数据时，单个站点抛出异常不应中断其余站点的刷新，
    且失败站点应被记录到错误日志中。
    """
    sites = [_site(1, "site-a"), _site(2, "site-b"), _site(3, "site-c")]

    sites_helper = Mock()
    sites_helper.get_indexers.return_value = sites
    monkeypatch.setattr(site_module, "SitesHelper", lambda: sites_helper)
    monkeypatch.setattr(site_module.eventmanager, "send_event", lambda *a, **k: None)

    chain = object.__new__(SiteChain)
    calls = []

    def _fake_refresh_userdata(site: dict):
        calls.append(site.get("name"))
        if site.get("name") == "site-b":
            raise RuntimeError("boom")
        return SimpleNamespace(ratio=None, user_level=None,
                               message_unread=0, message_unread_contents=None)

    monkeypatch.setattr(chain, "refresh_userdata", _fake_refresh_userdata)

    error_logs = []
    monkeypatch.setattr(site_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    result = chain.refresh_userdatas()

    # 三个站点都应被尝试处理，失败站点不应阻断后续站点
    assert calls == ["site-a", "site-b", "site-c"]
    # 未失败的站点结果应正常收集
    assert "site-a" in result
    assert "site-c" in result
    assert "site-b" not in result
    # 失败站点应被记录到错误日志，且带有站点标识
    assert any("site-b" in msg for msg in error_logs)


def test_sync_cookies_continues_after_one_domain_raises(monkeypatch) -> None:
    """
    CookieCloud 同步批量处理域名时，单个域名处理异常不应中断其余域名的同步，
    且失败域名应被记录到错误日志中。
    """
    cookies = {
        "domain-a.com": "cookie-a",
        "domain-b.com": "cookie-b",
        "domain-c.com": "cookie-c",
    }
    cookiecloud_helper = Mock()
    cookiecloud_helper.download.return_value = (cookies, None)
    monkeypatch.setattr(site_module, "CookieCloudHelper", lambda: cookiecloud_helper)

    sites_helper = Mock()

    def _get_indexer(domain: str):
        if domain == "domain-b.com":
            # 触发一个非预期异常，模拟索引器信息异常
            raise RuntimeError("indexer boom")
        return None

    sites_helper.get_indexer.side_effect = _get_indexer
    monkeypatch.setattr(site_module, "SitesHelper", lambda: sites_helper)

    site_oper = Mock()
    site_oper.get_by_domain.return_value = None
    monkeypatch.setattr(site_module, "SiteOper", lambda: site_oper)

    rss_helper = Mock()
    monkeypatch.setattr(site_module, "RssHelper", lambda: rss_helper)
    monkeypatch.setattr(site_module.eventmanager, "send_event", lambda *a, **k: None)

    chain = object.__new__(SiteChain)

    error_logs = []
    monkeypatch.setattr(site_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    status, msg = chain.sync_cookies(manual=False)

    # 三个域名都应被尝试处理（get_indexer 被调用三次）
    assert sites_helper.get_indexer.call_count == 3
    # 未受影响的域名不应因为 domain-b 异常而中断处理
    assert status is True
    assert any("domain-b.com" in log for log in error_logs)


def test_clear_site_data_continues_after_one_key_raises(monkeypatch) -> None:
    """
    清理站点关联配置时，单个配置键删除异常不应中断其余配置键的清理，
    且失败的配置键应被记录到错误日志中。
    """
    keys = ["site.example.name", "site.example.url", "site.example.cookie"]

    systemconfig = Mock()
    systemconfig.get.return_value = {k: "v" for k in keys}
    delete_calls = []

    def _delete(key: str):
        delete_calls.append(key)
        if key == "site.example.url":
            raise RuntimeError("boom")

    systemconfig.delete.side_effect = _delete
    monkeypatch.setattr(site_module, "get_configured_system_config", lambda: systemconfig)

    chain = object.__new__(SiteChain)
    event = SimpleNamespace(event_data={"domain": "example.com"})

    error_logs = []
    monkeypatch.setattr(site_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain.clear_site_data(event)

    # 三个配置键都应被尝试删除，单个失败不应中断其余删除
    assert delete_calls == keys
    assert any("site.example.url" in msg for msg in error_logs)
