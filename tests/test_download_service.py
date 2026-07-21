"""
S7h 抽取验证：app.service.download 的 Chain 编排单测（mock Chain）。

把 download/add 端点的「构建 Context → 识别媒体 → 提交 DownloadChain」编排下沉到
service 后，通过 monkeypatch MediaChain/DownloadChain 即可在 venv 内单测，无需真实
下载器/媒体识别。
"""
from types import SimpleNamespace

from app import schemas
from app.core.context import MediaInfo
from app.service import download as svc


def _torrent(title="Some.Movie.2020", description=""):
    return schemas.TorrentInfo(title=title, description=description)


def _media():
    return schemas.MediaInfo(title="Some Movie", year="2020")


def _truthy_media():
    mi = MediaInfo()
    mi.tmdb_id = 999
    return mi


def test_add_download_with_media_success(monkeypatch):
    captured = {}

    def fake_download_single(**kwargs):
        captured.update(kwargs)
        return "did-123"

    monkeypatch.setattr(
        svc, "DownloadChain", lambda: SimpleNamespace(download_single=fake_download_single)
    )
    did = svc.add_download_with_media(
        media_in=_media(),
        torrent_in=_torrent(),
        downloader="qb",
        save_path="/dl",
        username="alice",
    )
    assert did == "did-123"
    assert captured["username"] == "alice"
    assert captured["save_path"] == "/dl"
    assert captured["source"] == "Manual"
    # 选择的下载器写入 torrentinfo.site_downloader
    assert captured["context"].torrent_info.site_downloader == "qb"


def test_add_download_with_media_failure(monkeypatch):
    monkeypatch.setattr(
        svc, "DownloadChain", lambda: SimpleNamespace(download_single=lambda **kw: None)
    )
    did = svc.add_download_with_media(
        media_in=_media(),
        torrent_in=_torrent(),
        downloader=None,
        save_path=None,
        username="bob",
    )
    assert did is None


def test_recognize_and_download_recognize_fail(monkeypatch):
    called = {"dl": False}

    def fake_dl():
        called["dl"] = True
        return SimpleNamespace(download_single=lambda **kw: "x")

    monkeypatch.setattr(
        svc,
        "MediaChain",
        lambda: SimpleNamespace(
            recognize_by_meta=lambda meta, source=None, obtain_images=False: None,
            recognize_media=lambda **kw: None,
        ),
    )
    monkeypatch.setattr(svc, "DownloadChain", fake_dl)
    recognized, did = svc.recognize_and_download(
        torrent_in=_torrent(),
        tmdbid=None,
        doubanid=None,
        downloader=None,
        save_path=None,
        username="u",
    )
    assert recognized is False
    assert did is None
    assert called["dl"] is False  # 识别失败时不应提交下载


def test_recognize_and_download_by_meta_success(monkeypatch):
    monkeypatch.setattr(
        svc,
        "MediaChain",
        lambda: SimpleNamespace(
            recognize_by_meta=lambda meta, source=None, obtain_images=False: _truthy_media(),
            recognize_media=lambda **kw: None,
        ),
    )
    monkeypatch.setattr(
        svc, "DownloadChain", lambda: SimpleNamespace(download_single=lambda **kw: "did-abc")
    )
    recognized, did = svc.recognize_and_download(
        torrent_in=_torrent(),
        tmdbid=None,
        doubanid=None,
        downloader="tr",
        save_path="/x",
        username="u",
    )
    assert recognized is True
    assert did == "did-abc"


def test_recognize_and_download_by_tmdbid_uses_recognize_media(monkeypatch):
    calls = {}

    def fake_recognize_media(meta, tmdbid=None, doubanid=None, **kwargs):
        calls["tmdbid"] = tmdbid
        return _truthy_media()

    monkeypatch.setattr(
        svc,
        "MediaChain",
        lambda: SimpleNamespace(
            recognize_media=fake_recognize_media,
            recognize_by_meta=lambda **kw: None,
        ),
    )
    monkeypatch.setattr(
        svc, "DownloadChain", lambda: SimpleNamespace(download_single=lambda **kw: "did-tmdb")
    )
    recognized, did = svc.recognize_and_download(
        torrent_in=_torrent(),
        tmdbid=123,
        doubanid=None,
        downloader=None,
        save_path=None,
        username="u",
    )
    assert recognized is True
    assert did == "did-tmdb"
    assert calls["tmdbid"] == 123  # tmdbid/doubanid 分支走 recognize_media
