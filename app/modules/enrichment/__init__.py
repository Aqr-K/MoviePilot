"""媒体增补服务。

在核心识别与整理之外，为媒体补充单一信息的独立服务：图片、歌词、字幕、音频指纹、
收听榜单。

它们与下载器、媒体库、存储那几族不同——**彼此不可互换**：各自只提供一个别处没有的
能力，方法名两两不重合，也各有专属的处理链。本包按它们在管线中的位置归集，不表示
可替换关系；谁提供了哪个能力由 ``ModuleManager.get_capability_index()`` 如实记录。

模块扫描只遍历 ``app.modules`` 的一级条目，具体服务类须在此处导出才能进入注册表。
"""
from app.modules.enrichment.acoustid import AcoustIdModule
from app.modules.enrichment.fanart import FanartModule
from app.modules.enrichment.listenbrainz import ListenBrainzModule
from app.modules.enrichment.lrclib import LrclibModule
from app.modules.enrichment.subtitle import SubtitleModule

__all__ = [
    "AcoustIdModule",
    "FanartModule",
    "ListenBrainzModule",
    "LrclibModule",
    "SubtitleModule",
]
