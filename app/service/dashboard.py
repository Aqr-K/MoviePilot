"""
仪表盘统计的 Chain 编排 + 聚合逻辑（service layer）。

把媒体数量 / 本地存储 / 下载器统计的「调用 Chain/Helper 取数 + 聚合」编排从端点
下沉到服务层：端点退化为薄 HTTP 适配层、不再 import 任何 Chain；本层可通过 mock
DashboardChain/StorageChain/DirectoryHelper 进行单测，亦是后续 Rust 移植的稳定目标。
"""
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from app import schemas
from app.chain.dashboard import DashboardChain
from app.chain.storage import StorageChain
from app.db.models.transferhistory import TransferHistory
from app.helper.directory import DirectoryHelper
from app.utils.system import SystemUtils


def build_statistic(db: Session, name: Optional[str] = None) -> schemas.Statistic:
    """
    构建媒体数量统计信息。
    """
    media_statistics: Optional[List[schemas.Statistic]] = (
        DashboardChain().media_statistic(name)
    )
    if media_statistics:
        # 汇总各媒体库统计信息
        ret_statistic = schemas.Statistic()
        has_episode_count = False
        for media_statistic in media_statistics:
            ret_statistic.movie_count += media_statistic.movie_count or 0
            ret_statistic.tv_count += media_statistic.tv_count or 0
            ret_statistic.user_count += media_statistic.user_count or 0
            if media_statistic.episode_count is not None:
                ret_statistic.episode_count += media_statistic.episode_count or 0
                has_episode_count = True
        if not has_episode_count:
            # 所有媒体服务都未提供剧集统计时，返回 None 供前端展示“未获取”。
            ret_statistic.episode_count = None
    else:
        ret_statistic = schemas.Statistic()

    movie_count_month, tv_count_month, episode_count_month = TransferHistory.monthly_media_statistics(db)
    ret_statistic.movie_count_month = movie_count_month
    ret_statistic.tv_count_month = tv_count_month
    ret_statistic.episode_count_month = episode_count_month
    return ret_statistic


def build_storage() -> schemas.Storage:
    """
    构建本地存储空间信息。
    """
    total, available = 0, 0
    dirs = DirectoryHelper().get_dirs()
    if not dirs:
        return schemas.Storage(total_storage=total, used_storage=total - available)
    storages = set([d.library_storage for d in dirs if d.library_storage])
    for _storage in storages:
        _usage = StorageChain().storage_usage(_storage)
        if _usage:
            total += _usage.total
            available += _usage.available
    return schemas.Storage(total_storage=total, used_storage=total - available)


def build_downloader(name: Optional[str] = None) -> schemas.DownloaderInfo:
    """
    构建下载器统计信息。
    """
    # 下载目录空间
    download_dirs = DirectoryHelper().get_local_download_dirs()
    _, free_space = SystemUtils.space_usage(
        [Path(d.download_path) for d in download_dirs]
    )
    # 下载器信息
    downloader_info = schemas.DownloaderInfo()
    transfer_infos = DashboardChain().downloader_info(name)
    if transfer_infos:
        for transfer_info in transfer_infos:
            downloader_info.download_speed += transfer_info.download_speed
            downloader_info.upload_speed += transfer_info.upload_speed
            downloader_info.download_size += transfer_info.download_size
            downloader_info.upload_size += transfer_info.upload_size
        downloader_info.free_space = free_space
    return downloader_info
