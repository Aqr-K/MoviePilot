"""
跨授权和媒体交互用例复用的合成资源上下文。
"""

from app.domain.context import Context, MediaInfo, TorrentInfo
from app.domain.meta.metabase import MetaBase
from app.schemas.types import MediaType


def _build_context(title: str = "星际穿越") -> Context:
    """
    构造可用于媒体交互下载测试的资源上下文。
    """
    meta = MetaBase(title)
    meta.name = title
    meta.begin_season = 1
    return Context(
        meta_info=meta,
        media_info=MediaInfo(
            type=MediaType.MOVIE,
            title=title,
            year="2014",
            tmdb_id=1,
        ),
        torrent_info=TorrentInfo(
            title=f"{title}.2014.1080p",
            site_name="TestSite",
            enclosure="https://example.com/demo.torrent",
            seeders=10,
        ),
    )
