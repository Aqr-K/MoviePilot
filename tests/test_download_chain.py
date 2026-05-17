from pathlib import Path
from unittest.mock import MagicMock

import app.chain.download as download_module
from app.chain.download import DownloadChain
from app.core.context import Context, MediaInfo, TorrentInfo
from app.core.metainfo import MetaInfo
from app.schemas.types import MediaType


class _FakeDownloadHistoryOper:
    """
    避免单元测试写入真实下载历史，只验证下载链路的控制流。
    """

    def add(self, **_kwargs):
        pass

    def add_files(self, _files):
        pass


class _FakeTorrentHelper:
    """
    避免解析真实种子内容，让测试聚焦下载成功后的后台处理。
    """

    def get_fileinfo_from_torrent_content(self, _torrent_content):
        return "", []


class _FakeThreadHelper:
    """
    捕获提交到线程池的任务，测试中手动触发以避免真正启动后台线程。
    """

    submitted = []

    def submit(self, func, *args, **kwargs):
        self.submitted.append((func, args, kwargs))


def test_download_single_submits_download_added_to_background(monkeypatch):
    """
    添加下载成功后，站点字幕等后处理应提交到后台，不能阻塞下载接口返回。
    """
    _FakeThreadHelper.submitted = []
    monkeypatch.setattr(download_module, "ThreadHelper", _FakeThreadHelper)
    monkeypatch.setattr(download_module, "DownloadHistoryOper", _FakeDownloadHistoryOper)
    monkeypatch.setattr(download_module, "TorrentHelper", _FakeTorrentHelper)

    chain = DownloadChain.__new__(DownloadChain)
    chain.download = MagicMock(return_value=("qb", "hash123", "Original", "添加下载成功"))
    chain.download_added = MagicMock()
    chain.eventmanager = MagicMock()
    chain.eventmanager.send_event.return_value = None
    chain.post_message = MagicMock()

    context = Context(
        meta_info=MetaInfo("Demo Movie 2024"),
        media_info=MediaInfo(
            type=MediaType.MOVIE,
            title="Demo Movie",
            year="2024",
            tmdb_id=1,
            genre_ids=[18],
        ),
        torrent_info=TorrentInfo(
            title="Demo Movie 2024",
            enclosure="https://example.com/demo.torrent",
            site_cookie="uid=1",
            site_name="TestSite",
        ),
    )

    result = chain.download_single(
        context=context,
        torrent_content=b"torrent-content",
        save_path="/downloads",
        username="tester",
    )

    assert result == "hash123"
    chain.download_added.assert_not_called()
    assert len(_FakeThreadHelper.submitted) == 1

    task, args, kwargs = _FakeThreadHelper.submitted[0]
    assert args == ()
    assert kwargs == {}

    task()

    chain.download_added.assert_called_once_with(
        context=context,
        download_dir=Path("/downloads"),
        torrent_content=b"torrent-content",
    )
