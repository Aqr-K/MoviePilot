from pathlib import Path
from typing import Optional, List, Tuple, Union, Dict

from app.runtime.config import settings
from app.domain.context import MediaInfo, MusicInfo
from app.domain.meta.metamusic import MetaMusic
from app.domain.metainfo import MetaInfo
from app.application.directory import DirectoryHelper
from app.application.messaging.message import MessageHelper
from app.runtime.log import logger
from app.modules import _ModuleBase
from app.modules.storages import get_storage
from app.application.transfer.handler import TransHandler
from app.schemas import ExistMediaInfo, FileItem
from app.schemas.types import MUSIC_ENTITY_ALBUM, MediaType, ModuleType, OtherModulesType
from app.adapters.system.host import SystemUtils
from app.foundation import text as text_tools


class FileManagerModule(_ModuleBase):
    """
    文件整理模块
    """

    def __init__(self):
        super().__init__()
        self.directoryhelper = DirectoryHelper()
        self.messagehelper = MessageHelper()

    def init_module(self) -> None:
        """初始化文件整理模块"""
        pass

    @staticmethod
    def get_name() -> str:
        """获取模块名称"""
        return "文件整理"

    @staticmethod
    def get_type() -> ModuleType:
        """
        获取模块类型
        """
        return ModuleType.Other

    @staticmethod
    def get_subtype() -> OtherModulesType:
        """
        获取模块子类型
        """
        return OtherModulesType.FileManager

    @staticmethod
    def get_priority() -> int:
        """
        获取模块优先级，数字越小优先级越高，只有同一接口下优先级才生效
        """
        return 4

    def stop(self):
        """停止文件整理模块"""
        pass

    def test(self) -> Tuple[bool, str]:
        """
        测试模块连接性
        """
        # 检查目录
        dirs = self.directoryhelper.get_dirs()
        if not dirs:
            return False, "未设置任何目录"
        for d in dirs:
            # 下载目录
            download_path = d.download_path
            if not download_path:
                return False, f"{d.name} 的下载目录未设置"
            if d.storage == "local" and not Path(download_path).exists():
                return False, f"{d.name} 的下载目录 {download_path} 不存在"
            # 仅在启用整理时检查媒体库目录
            library_path = d.library_path
            if d.transfer_type:
                if not library_path:
                    return False, f"{d.name} 的媒体库目录未设置"
                if d.library_storage == "local" and not Path(library_path).exists():
                    return False, f"{d.name} 的媒体库目录 {library_path} 不存在"
                # 硬链接
                if d.transfer_type == "link" \
                        and d.storage == "local" \
                        and d.library_storage == "local" \
                        and not SystemUtils.is_same_disk(Path(download_path), Path(library_path)):
                    return False, f"{d.name} 的下载目录 {download_path} 与媒体库目录 {library_path} 不在同一磁盘，无法硬链接"
            # 存储
            storage_oper = get_storage(d.storage)
            if storage_oper:
                if not storage_oper.check():
                    return False, f"{d.name} 的存储测试不通过"
                if d.transfer_type and d.transfer_type not in storage_oper.support_transtype():
                    return False, f"{d.name} 的存储不支持 {d.transfer_type} 整理方式"

        return True, ""

    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        pass

    @staticmethod
    def _music_file_identity(fileitem: FileItem) -> Tuple[Optional[int], Optional[int], str]:
        """从标准音乐文件路径提取碟号、曲序和归一化曲名。"""
        file_path = Path(fileitem.path or fileitem.name or "")
        file_meta = MetaMusic(
            org_string=file_path.name,
            title=file_path.stem,
        ).apply_path_context(file_path)
        return (
            file_meta.disc_number,
            file_meta.track_number,
            text_tools.normalize_upper(file_meta.title or file_path.stem),
        )

    @classmethod
    def _music_recording_exists(
            cls,
            fileitems: List[FileItem],
            mediainfo: MusicInfo,
    ) -> bool:
        """按曲名和可用曲序判断单曲是否存在，避免专辑内任一文件造成误判。"""
        target_title = text_tools.normalize_upper(mediainfo.title or "")
        target_track = getattr(mediainfo, "track_number", None)
        target_disc = getattr(mediainfo, "disc_number", None)
        if not target_title:
            return False
        for fileitem in fileitems:
            disc_number, track_number, title = cls._music_file_identity(fileitem)
            if title != target_title:
                continue
            if target_track is not None and track_number not in (None, target_track):
                continue
            if target_disc is not None and disc_number not in (None, target_disc):
                continue
            return True
        return False

    @classmethod
    def _music_album_is_complete(
            cls,
            fileitems: List[FileItem],
            total_tracks: Optional[int],
    ) -> bool:
        """按去重后的曲序或曲名判断本地专辑是否达到目标曲目数。"""
        if not fileitems:
            return False
        if not total_tracks:
            return False
        track_identities = {
            (
                disc_number or 1,
                track_number if track_number is not None else title,
            )
            for disc_number, track_number, title in (
                cls._music_file_identity(fileitem) for fileitem in fileitems
            )
            if track_number is not None or title
        }
        return len(track_identities) >= total_tracks

    def media_exists(
            self,
            mediainfo: Union[MediaInfo, MusicInfo],
            **kwargs,
    ) -> Optional[ExistMediaInfo]:
        """
        判断媒体文件是否存在于文件系统（网盘或本地文件），只支持标准媒体库结构
        :param mediainfo:  识别的媒体信息
        :param server:  指定媒体服务器名称时跳过本地文件系统检查
        :return: 如不存在返回None，存在时返回信息，包括每季已存在所有集{type: movie/tv, seasons: {season: [episodes]}}
        """
        if kwargs.get("server"):
            return None

        if not settings.LOCAL_EXISTS_SEARCH:
            return None

        logger.debug(f"正在本地媒体库中查找 {mediainfo.title_year}...")

        # 检查媒体库
        fileitems = TransHandler().media_files(mediainfo)
        if not fileitems:
            logger.debug(f"{mediainfo.title_year} 不在本地媒体库中")
            return None

        if mediainfo.type == MediaType.MOVIE:
            # 电影存在任何文件为存在
            logger.info(f"{mediainfo.title_year} 在本地文件系统中找到了")
            return ExistMediaInfo(type=MediaType.MOVIE)
        if mediainfo.type == MediaType.MUSIC:
            if getattr(mediainfo, "music_type", None) == MUSIC_ENTITY_ALBUM:
                exists = self._music_album_is_complete(
                    fileitems,
                    getattr(mediainfo, "total_tracks", None),
                )
            else:
                exists = self._music_recording_exists(fileitems, mediainfo)
            if not exists:
                logger.debug(f"{mediainfo.title_year} 在本地音乐库中尚不完整")
                return None
            logger.info(f"{mediainfo.title_year} 在本地音乐库中找到了")
            return ExistMediaInfo(type=MediaType.MUSIC)
        if mediainfo.type == MediaType.TV:
            # 电视剧检索集数
            seasons: Dict[int, list] = {}
            for fileitem in fileitems:
                file_meta = MetaInfo(fileitem.basename)
                season_index = file_meta.begin_season if file_meta.begin_season is not None else 1
                episode_index = file_meta.begin_episode
                if not episode_index:
                    continue
                if season_index not in seasons:
                    seasons[season_index] = []
                if episode_index not in seasons[season_index]:
                    seasons[season_index].append(episode_index)
            # 返回剧集情况
            logger.info(f"{mediainfo.title_year} 在本地文件系统中找到了这些季集：{seasons}")
            return ExistMediaInfo(type=MediaType.TV, seasons=seasons)
        return None
