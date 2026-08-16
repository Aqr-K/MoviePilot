"""媒体服务器。

每个媒体服务器是一个独立模块，以媒体服务器类型作为模块子类型。
模块扫描只遍历 ``app.modules`` 的一级条目，具体媒体服务器类须在此处导出才能进入注册表。
"""
from app.modules.mediaservers.emby import EmbyModule
from app.modules.mediaservers.jellyfin import JellyfinModule
from app.modules.mediaservers.navidrome import NavidromeModule
from app.modules.mediaservers.plex import PlexModule
from app.modules.mediaservers.trimemedia import TrimeMediaModule
from app.modules.mediaservers.ugreen import UgreenModule
from app.modules.mediaservers.zspace import ZSpaceModule

__all__ = [
    "EmbyModule",
    "JellyfinModule",
    "NavidromeModule",
    "PlexModule",
    "TrimeMediaModule",
    "UgreenModule",
    "ZSpaceModule",
]
