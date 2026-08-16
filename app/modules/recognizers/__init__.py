"""媒体识别源。

每个识别源是一个独立模块，以识别源类型作为模块子类型。
模块扫描只遍历 ``app.modules`` 的一级条目，具体识别源类须在此处导出才能进入注册表。
"""
from app.modules.recognizers.anilist import AniListModule
from app.modules.recognizers.bangumi import BangumiModule
from app.modules.recognizers.douban import DoubanModule
from app.modules.recognizers.doubanmusic import DoubanMusicModule
from app.modules.recognizers.musicbrainz import MusicBrainzModule
from app.modules.recognizers.theaudiodb import TheAudioDbModule
from app.modules.recognizers.themoviedb import TheMovieDbModule
from app.modules.recognizers.thetvdb import TheTvDbModule

__all__ = [
    "AniListModule",
    "BangumiModule",
    "DoubanModule",
    "DoubanMusicModule",
    "MusicBrainzModule",
    "TheAudioDbModule",
    "TheMovieDbModule",
    "TheTvDbModule",
]
