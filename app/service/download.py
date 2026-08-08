"""
下载提交的 Chain 编排（service layer）。

把「构建 Context → （可选）识别媒体 → 提交 DownloadChain」的编排从端点下沉到服务层：
端点退化为薄 HTTP 适配层、不再 import MediaChain/MetaInfo；本层可通过 mock
MediaChain/DownloadChain 单测，亦是后续 Rust 移植的稳定目标。
"""
from typing import Optional, Tuple, Union

from app import schemas
from app.chain.download import DownloadChain
from app.chain.media import MediaChain
from app.chain.music import MusicChain
from app.core.context import Context, MediaInfo, SubtitleInfo, TorrentInfo
from app.core.metainfo import MetaInfo
from app.core.music import MusicInfo
from app.db.site_oper import SiteOper
from app.utils.security import SecurityUtils


def add_download_with_media(
    media_in: Union[schemas.MusicInfo, schemas.MediaInfo],
    torrent_in: schemas.TorrentInfo,
    downloader: Optional[str],
    save_path: Optional[str],
    username: str,
) -> Optional[str]:
    """
    添加下载（含媒体信息）：构建上下文并提交 DownloadChain，返回 download_id 或 None。
    音乐信息由 MusicChain 构造元数据，其它类型走 MetaInfo 解析种子标题。
    """
    if isinstance(media_in, schemas.MusicInfo):
        mediainfo = MusicInfo.from_dict(media_in.model_dump())
        metainfo = MusicChain.to_meta(mediainfo)
        metainfo.org_string = torrent_in.title
    else:
        # 元数据
        metainfo = MetaInfo(title=torrent_in.title, subtitle=torrent_in.description)
        # 媒体信息
        mediainfo = MediaInfo()
        mediainfo.from_dict(media_in.model_dump())
    # 种子信息
    torrentinfo = TorrentInfo()
    torrentinfo.from_dict(torrent_in.model_dump())
    # 手动下载始终使用选择的下载器
    torrentinfo.site_downloader = downloader
    # 上下文
    context = Context(
        meta_info=metainfo, media_info=mediainfo, torrent_info=torrentinfo
    )
    return DownloadChain().download_single(
        context=context,
        username=username,
        save_path=save_path,
        source="Manual",
    )


def recognize_and_download(
    torrent_in: schemas.TorrentInfo,
    tmdbid: Optional[int],
    doubanid: Optional[str],
    downloader: Optional[str],
    save_path: Optional[str],
    username: str,
    media_source: Optional[str] = None,
    media_id: Optional[str] = None,
    bangumiid: Optional[int] = None,
    anilistid: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    """
    添加下载（不含媒体信息）：识别媒体 → 构建上下文 → 提交 DownloadChain。

    :param media_source: 请求级识别数据源
    :param media_id: 与 media_source 配套的数据源原生ID
    :param bangumiid: Bangumi 兼容ID
    :param anilistid: AniList 兼容ID
    :return: (recognized, download_id)；recognized=False 表示识别失败
    """
    # 元数据
    metainfo = MetaInfo(title=torrent_in.title, subtitle=torrent_in.description)
    # 媒体信息
    if tmdbid or doubanid or bangumiid or anilistid or media_id:
        mediainfo = MediaChain().recognize_media(
            meta=metainfo,
            source=media_source,
            mediaid=media_id,
            tmdbid=tmdbid,
            doubanid=doubanid,
            bangumiid=bangumiid,
            anilistid=anilistid,
        )
    else:
        mediainfo = MediaChain().recognize_by_meta(
            metainfo,
            source=media_source,
            obtain_images=False,
        )
    if not mediainfo:
        return False, None
    # 种子信息
    torrentinfo = TorrentInfo()
    torrentinfo.from_dict(torrent_in.model_dump())
    # 上下文
    context = Context(
        meta_info=metainfo, media_info=mediainfo, torrent_info=torrentinfo
    )
    did = DownloadChain().download_single(
        context=context,
        username=username,
        downloader=downloader,
        save_path=save_path,
        source="Manual",
    )
    return True, did


def prepare_subtitle_download(subtitle: SubtitleInfo) -> Tuple[bool, str]:
    """
    校验字幕下载签名，并用服务端站点配置覆盖请求凭据。
    """
    if subtitle.site is None:
        return False, "字幕站点信息为空"

    clean_url = SecurityUtils.verify_signed_url(
        subtitle.enclosure,
        purpose=SecurityUtils.subtitle_download_purpose(subtitle.site),
    )
    if not clean_url:
        return False, "字幕下载链接签名无效"

    site = SiteOper().get(subtitle.site)
    if not site:
        return False, "字幕站点信息不存在"

    subtitle.enclosure = clean_url
    subtitle.site_cookie = site.cookie
    subtitle.site_ua = site.ua
    subtitle.site_proxy = bool(site.proxy)
    return True, ""
