import asyncio
import json
from unittest.mock import MagicMock, patch

from app.agent.tools.impl.query_download_tasks import QueryDownloadTasksTool
from app.schemas import DownloaderTorrent


def test_completed_status_returns_qbittorrent_and_transmission_completed_states():
    """
    按完成状态查询时应包含 QB/TR 中非下载中、非暂停的实际状态。
    """
    completed_torrents = [
        DownloaderTorrent(
            downloader="qb",
            hash="hash-qb",
            title="QB Done",
            size=1024,
            progress=100,
            state="completed",
            tags="moviepilot",
        ),
        DownloaderTorrent(
            downloader="tr",
            hash="hash-tr",
            title="TR Done",
            size=2048,
            progress=100,
            state="completed",
            tags="moviepilot",
        ),
    ]
    download_chain = MagicMock()
    download_chain.list_torrents.return_value = completed_torrents

    with patch(
        "app.agent.tools.impl.query_download_tasks.DownloadChain",
        return_value=download_chain,
    ), patch.object(
        QueryDownloadTasksTool,
        "_load_history_map",
        return_value={},
    ):
        result = QueryDownloadTasksTool._query_downloads_sync(status="completed")

    assert result["downloads"] == completed_torrents
    download_chain.list_torrents.assert_called_once_with(
        downloader=None,
        status="completed",
        include_all_tags=False,
    )


def test_run_completed_status_formats_completed_download_tasks():
    """
    工具输出应保留完成任务的实际下载器状态，便于用户判断来源。
    """
    completed_torrents = [
        DownloaderTorrent(
            downloader="qb",
            hash="hash-qb",
            title="QB Done",
            size=1024,
            progress=100,
            state="completed",
            tags="moviepilot",
        )
    ]

    with patch.object(
        QueryDownloadTasksTool,
        "_query_downloads_sync",
        return_value={"downloads": completed_torrents},
    ):
        result = asyncio.run(
            QueryDownloadTasksTool(session_id="session-1", user_id="10001").run(
                status="completed"
            )
        )

    payload = json.loads(result)
    assert payload[0]["hash"] == "hash-qb"
    assert payload[0]["state"] == "completed"


def test_include_all_tags_passes_scope_to_downloader_query():
    """
    智能体显式扩大范围时，应查询未打 MoviePilot 内置标签的下载任务。
    """
    all_scope_torrents = [
        DownloaderTorrent(
            downloader="qb",
            hash="hash-external",
            title="External Task",
            size=1024,
            progress=10,
            state="downloading",
            tags="external",
        )
    ]
    download_chain = MagicMock()
    download_chain.list_torrents.return_value = all_scope_torrents

    with patch(
        "app.agent.tools.impl.query_download_tasks.DownloadChain",
        return_value=download_chain,
    ), patch.object(
        QueryDownloadTasksTool,
        "_load_history_map",
        return_value={},
    ):
        result = QueryDownloadTasksTool._query_downloads_sync(
            status="all",
            include_all_tags=True,
        )

    assert result["downloads"] == all_scope_torrents
    download_chain.list_torrents.assert_called_once_with(
        downloader=None,
        status=None,
        include_all_tags=True,
    )


def test_include_all_tags_downloading_status_uses_list_torrents():
    """
    查询全部标签范围的下载中任务时，不应走只面向 MoviePilot 任务的便捷方法。
    """
    download_chain = MagicMock()
    download_chain.list_torrents.return_value = [
        DownloaderTorrent(
            downloader="tr",
            hash="hash-downloading",
            title="Downloading External",
            size=2048,
            progress=50,
            state="downloading",
            tags="external",
        )
    ]

    with patch(
        "app.agent.tools.impl.query_download_tasks.DownloadChain",
        return_value=download_chain,
    ), patch.object(
        QueryDownloadTasksTool,
        "_load_history_map",
        return_value={},
    ):
        result = QueryDownloadTasksTool._query_downloads_sync(
            status="downloading",
            include_all_tags=True,
        )

    assert result["downloads"][0].hash == "hash-downloading"
    download_chain.downloading.assert_not_called()
    download_chain.list_torrents.assert_called_once_with(
        downloader=None,
        status="downloading",
        include_all_tags=True,
    )


def test_include_all_tags_false_string_keeps_builtin_tag_scope():
    """
    CLI 字符串 false 不应被 Python 真值规则误判为扩大查询范围。
    """
    download_chain = MagicMock()
    download_chain.list_torrents.return_value = [
        DownloaderTorrent(
            downloader="qb",
            hash="hash-moviepilot",
            title="MoviePilot Task",
            size=1024,
            progress=100,
            state="completed",
            tags="moviepilot",
        )
    ]

    with patch(
        "app.agent.tools.impl.query_download_tasks.DownloadChain",
        return_value=download_chain,
    ), patch.object(
        QueryDownloadTasksTool,
        "_load_history_map",
        return_value={},
    ):
        result = QueryDownloadTasksTool._query_downloads_sync(
            status="completed",
            include_all_tags="false",
        )

    assert result["downloads"][0].hash == "hash-moviepilot"
    download_chain.list_torrents.assert_called_once_with(
        downloader=None,
        status="completed",
        include_all_tags=False,
    )
