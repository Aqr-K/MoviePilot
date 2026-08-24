"""站点种子刷新的并发抓取与单站点故障隔离测试。"""

import threading
import time
from typing import Dict, List, Optional
from unittest.mock import Mock, patch

from app.application.orchestration.torrents import TorrentsChain
from app.domain.context import TorrentInfo
from app.schemas.types import MediaType


def _indexer(index: int) -> dict:
    """构造一个最小可用的站点索引配置。"""
    return {
        "id": index,
        "name": f"Site{index}",
        "domain": f"https://site{index}.com",
    }


def _domain(index: int) -> str:
    """返回站点索引配置对应的匹配域名。"""
    return f"site{index}.com"


def _site_index(domain: str) -> int:
    """从匹配域名还原站点序号。"""
    return int(domain[len("site"):-len(".com")])


def _torrent(index: int) -> TorrentInfo:
    """构造一条属于指定站点的影视种子。"""
    return TorrentInfo(
        site=index,
        site_name=f"Site{index}",
        title=f"Some.Movie.S{index}.2026.1080p",
        enclosure=f"https://site{index}.com/download?id={index}",
        category=MediaType.MOVIE.value,
        pubdate="2026-08-07 00:00:00",
    )


def _sites_helper(count: int) -> Mock:
    """构造返回指定数量站点的站点助手替身。"""
    helper = Mock()
    helper.get_indexers.return_value = [_indexer(i) for i in range(1, count + 1)]
    return helper


def test_refresh_isolates_single_site_recognize_failure():
    """单个站点识别抛异常时，其余站点的刷新结果仍应完整返回。"""
    chain = TorrentsChain()

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """首页返回该站点的一条种子，第二页为空以结束翻页。"""
        return [] if page else [_torrent(_site_index(domain))]

    def _fake_recognize(meta, obtain_images=False):
        """站点2的种子识别失败，其余站点识别不到媒体信息。"""
        if "S2" in (meta.org_string or ""):
            raise RuntimeError("识别服务异常")
        return None

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(3)),
        patch("app.application.orchestration.torrents.MediaChain") as media_chain,
    ):
        media_chain.return_value.recognize_by_meta.side_effect = _fake_recognize
        result = chain.refresh(stype="spider", sites=[1, 2, 3])

    assert set(result) == {_domain(1), _domain(3)}
    assert result[_domain(1)][0].torrent_info.title == "Some.Movie.S1.2026.1080p"
    assert result[_domain(3)][0].torrent_info.title == "Some.Movie.S3.2026.1080p"


def test_refresh_isolates_single_site_fetch_failure():
    """单个站点抓取抛异常时，其余站点的刷新结果仍应完整返回。"""
    chain = TorrentsChain()

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """站点2抓取失败，其余站点首页返回一条种子。"""
        if _site_index(domain) == 2:
            raise RuntimeError("站点连接超时")
        return [] if page else [_torrent(_site_index(domain))]

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(3)),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        result = chain.refresh(stype="spider", sites=[1, 2, 3])

    assert set(result) == {_domain(1), _domain(3)}


def test_refresh_fetches_sites_concurrently():
    """多个站点的抓取应并发执行，全部站点需能同时到达同一同步点。"""
    chain = TorrentsChain()
    site_count = 4
    barrier = threading.Barrier(site_count, timeout=10)

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """首页抓取阻塞在栅栏上，串行执行时无法全部通过。"""
        if not page:
            barrier.wait()
            return [_torrent(_site_index(domain))]
        return []

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(site_count)),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        result = chain.refresh(stype="spider", sites=list(range(1, site_count + 1)))

    assert set(result) == {_domain(i) for i in range(1, site_count + 1)}


def test_refresh_keeps_requests_sequential_within_one_site():
    """同一站点内部的分页请求必须顺序执行，不得对单站点加压。"""
    chain = TorrentsChain()
    site_count = 3
    lock = threading.Lock()
    active: Dict[str, int] = {}
    overlapped: List[str] = []
    call_pages: Dict[str, List[Optional[int]]] = {}

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """记录单站点内并发请求数与分页调用顺序。"""
        with lock:
            active[domain] = active.get(domain, 0) + 1
            if active[domain] > 1:
                overlapped.append(domain)
            call_pages.setdefault(domain, []).append(page)
        time.sleep(0.02)
        with lock:
            active[domain] -= 1
        return [_torrent(_site_index(domain))]

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(site_count)),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        chain.refresh(stype="spider", sites=list(range(1, site_count + 1)))

    assert overlapped == []
    for index in range(1, site_count + 1):
        assert call_pages[_domain(index)] == [0, 1]


def test_refresh_preserves_indexer_order_in_result():
    """并发抓取后的结果仍应按站点索引顺序合并，避免结果次序随机化。"""
    chain = TorrentsChain()
    site_count = 4
    delays = {1: 0.06, 2: 0.04, 3: 0.02, 4: 0.0}

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """靠前的站点抓取更慢，用于放大完成次序与索引次序的差异。"""
        if page:
            return []
        time.sleep(delays[_site_index(domain)])
        return [_torrent(_site_index(domain))]

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(site_count)),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        result = chain.refresh(stype="spider", sites=list(range(1, site_count + 1)))

    assert list(result) == [_domain(i) for i in range(1, site_count + 1)]


def test_refresh_without_any_site_returns_empty_cache():
    """没有可刷新站点时线程池仍需可用，刷新应返回空缓存而不是报错。"""
    chain = TorrentsChain()
    sites_helper = Mock()
    sites_helper.get_indexers.return_value = []

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse") as browse,
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=sites_helper),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        result = chain.refresh(stype="spider", sites=[1])

    assert result == {}
    browse.assert_not_called()


def test_refresh_reports_progress_for_every_site():
    """刷新进度回调应覆盖全部站点，失败站点也要计入完成数。"""
    chain = TorrentsChain()
    site_count = 3
    events: List[dict] = []

    def _fake_browse(domain, keyword=None, cat=None, page=None, mtype=None):
        """站点2抓取失败，其余站点首页返回一条种子。"""
        if _site_index(domain) == 2:
            raise RuntimeError("站点连接超时")
        return [] if page else [_torrent(_site_index(domain))]

    def _progress(value=None, text=None, data=None):
        """记录进度回调的原始数据。"""
        events.append(data or {})

    with (
        patch.object(chain, "load_cache", return_value=None),
        patch.object(chain, "browse", side_effect=_fake_browse),
        patch.object(chain, "save_cache"),
        patch("app.application.orchestration.torrents.SitesHelper",
              return_value=_sites_helper(site_count)),
        patch("app.application.orchestration.torrents.MediaChain"),
    ):
        chain.refresh(stype="spider", sites=[1, 2, 3], progress_callback=_progress)

    assert [event.get("current") for event in events if "current" in event] == [1, 2, 3]
    assert events[-1] == {"total": site_count, "finished": site_count}
