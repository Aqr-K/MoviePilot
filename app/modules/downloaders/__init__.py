"""下载器。

每个下载器是一个独立模块，以下载器类型作为模块子类型。
模块扫描只遍历 ``app.modules`` 的一级条目，具体下载器类须在此处导出才能进入注册表。
"""
from app.modules.downloaders.qbittorrent import QbittorrentModule
from app.modules.downloaders.rtorrent import RtorrentModule
from app.modules.downloaders.transmission import TransmissionModule

__all__ = [
    "QbittorrentModule",
    "RtorrentModule",
    "TransmissionModule",
]
