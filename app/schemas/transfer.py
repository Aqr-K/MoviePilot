from pathlib import Path
from typing import Optional, List, Any, Callable

from pydantic import BaseModel, Field

from app.schemas.context import MetaInfo, MediaInfo
from app.schemas.file import FileItem
from app.schemas.history import DownloadHistory
from app.schemas.system import TransferDirectoryConf
from app.schemas.tmdb import TmdbEpisode


class TransferTorrent(BaseModel):
    """
    待转移任务信息
    """
    downloader: Optional[str] = None
    title: Optional[str] = None
    path: Optional[Path] = None
    hash: Optional[str] = None
    tags: Optional[str] = None
    size: Optional[int] = 0
    userid: Optional[str] = None
    progress: Optional[float] = 0.0
    state: Optional[str] = None


class DownloadingTorrent(BaseModel):
    """
    下载中任务信息
    """
    downloader: Optional[str] = None
    hash: Optional[str] = None
    title: Optional[str] = None
    name: Optional[str] = None
    year: Optional[str] = None
    season_episode: Optional[str] = None
    size: Optional[float] = 0.0
    progress: Optional[float] = 0.0
    state: Optional[str] = 'downloading'
    upspeed: Optional[str] = None
    dlspeed: Optional[str] = None
    tags: Optional[str] = None
    media: Optional[dict] = Field(default_factory=dict)
    userid: Optional[str] = None
    username: Optional[str] = None
    left_time: Optional[str] = None


class TransferTask(BaseModel):
    """
    文件整理任务
    """
    fileitem: FileItem
    meta: Optional[Any] = None
    mediainfo: Optional[Any] = None
    target_directory: Optional[TransferDirectoryConf] = None
    target_storage: Optional[str] = None
    target_path: Optional[Path] = None
    transfer_type: Optional[str] = None
    scrape: Optional[bool] = False
    library_type_folder: Optional[bool] = False
    library_category_folder: Optional[bool] = False
    episodes_info: Optional[List[TmdbEpisode]] = None
    username: Optional[str] = None
    downloader: Optional[str] = None
    download_hash: Optional[str] = None
    download_history: Optional[DownloadHistory] = None
    transfer_batch_id: Optional[str] = None
    manual: Optional[bool] = False
    background: Optional[bool] = True
    preview: Optional[bool] = False

    def to_dict(self):
        """
        返回字典
        """
        dicts = vars(self).copy()
        dicts["fileitem"] = self.fileitem.model_dump() if self.fileitem else None
        dicts["meta"] = self.meta.model_dump() if self.meta else None
        dicts["mediainfo"] = self.mediainfo.model_dump() if self.mediainfo else None
        dicts["target_directory"] = self.target_directory.model_dump() if self.target_directory else None
        return dicts


class TransferJobTask(BaseModel):
    """
    文件整理作业任务
    """
    fileitem: Optional[FileItem] = None
    meta: Optional[MetaInfo] = None
    state: Optional[str] = None
    downloader: Optional[str] = None
    download_hash: Optional[str] = None


class TransferJob(BaseModel):
    """
    文件整理作业
    """
    media: Optional[MediaInfo] = None
    season: Optional[int] = None
    tasks: Optional[List[TransferJobTask]] = Field(default_factory=list)


class TransferInfo(BaseModel):
    """
    文件整理结果
    """
    # 是否成功标志
    success: bool = True
    # 整理⼁路径
    fileitem: Optional[FileItem] = None
    # 转移后的目录项，媒体的根目录
    target_diritem: Optional[FileItem] = None
    # 转移后路径
    target_item: Optional[FileItem] = None
    # 整理方式
    transfer_type: Optional[str] = None
    # 处理文件数
    file_count: Optional[int] = Field(default=0)
    # 处理文件清单
    file_list: Optional[list] = Field(default_factory=list)
    # 目标文件清单
    file_list_new: Optional[list] = Field(default_factory=list)
    # 总文件大小
    total_size: Optional[int] = Field(default=0)
    # 失败清单
    fail_list: Optional[list] = Field(default_factory=list)
    # 错误信息
    message: Optional[str] = None
    # 是否需要刮削
    need_scrape: Optional[bool] = False
    # 是否需要通知
    need_notify: Optional[bool] = False

    def ensure_target_items(self):
        """
        补齐整理目标文件项和目录项，兼容 OpenList 等成功后元数据延迟可见的存储。
        """
        if not self.target_item or not self.target_item.path:
            self.target_item = self.__build_target_item()
        if not self.target_diritem or not self.target_diritem.path:
            self.target_diritem = self.__build_target_diritem()
        return self

    def __build_target_item(self) -> Optional[FileItem]:
        """
        根据目标文件清单构造整理目标文件项。
        """
        if self.target_item and self.target_item.path:
            return self.target_item
        if not self.file_list_new:
            return self.target_item

        target_path = self.file_list_new[0]
        if not target_path:
            return self.target_item

        path = Path(str(target_path))
        source_item = self.fileitem
        return FileItem(
            storage=self.__get_target_storage(),
            path=path.as_posix(),
            type=source_item.type if source_item and source_item.type else "file",
            name=path.name,
            basename=path.stem,
            extension=path.suffix.lstrip("."),
            size=source_item.size if source_item else None,
            modify_time=source_item.modify_time if source_item else None,
            thumbnail=source_item.thumbnail if source_item else None,
        )

    def __build_target_diritem(self) -> Optional[FileItem]:
        """
        根据目标文件项或目标文件清单构造整理目标目录项。
        """
        if self.target_diritem and self.target_diritem.path:
            return self.target_diritem

        target_dir_path = self.__get_target_dir_path()
        if not target_dir_path:
            return self.target_diritem

        path = Path(str(target_dir_path))
        return FileItem(
            storage=self.__get_target_storage(),
            path=path.as_posix(),
            type="dir",
            name=path.name,
            basename=path.stem,
        )

    def __get_target_dir_path(self) -> Optional[str]:
        """
        从已知整理结果中推导媒体目标目录路径。
        """
        if self.target_item and self.target_item.path:
            if self.target_item.type == "dir":
                return self.target_item.path
            return Path(str(self.target_item.path)).parent.as_posix()
        if self.file_list_new:
            return Path(str(self.file_list_new[0])).parent.as_posix()
        return None

    def __get_target_storage(self) -> str:
        """
        从目标项、目标目录项或源文件项中推导目标存储标识。
        """
        if self.target_item and self.target_item.storage:
            return self.target_item.storage
        if self.target_diritem and self.target_diritem.storage:
            return self.target_diritem.storage
        if self.fileitem and self.fileitem.storage:
            return self.fileitem.storage
        return "local"

    def to_dict(self):
        """
        返回字典
        """
        dicts = vars(self).copy()
        dicts["fileitem"] = self.fileitem.model_dump() if self.fileitem else None
        dicts["target_item"] = self.target_item.model_dump() if self.target_item else None
        return dicts


class TransferQueue(BaseModel):
    """
    异步整理队列信息
    """
    # 任务信息
    task: Optional[TransferTask] = None
    # 回调函数
    callback: Optional[Callable] = None
    # 整理结果
    result: Optional[TransferInfo] = None


class EpisodeFormat(BaseModel):
    """
    剧集自定义识别格式
    """
    format: Optional[str] = None
    detail: Optional[str] = None
    part: Optional[str] = None
    offset: Optional[str] = None


class EpisodeFormatRule(BaseModel):
    """
    集数定位规则
    """
    name: str
    enabled: bool = True
    order: int = 0
    pattern: str
    min_file_size_mb: int = 0


class EpisodeFormatRecommendItem(BaseModel):
    """
    集数定位推荐请求
    """
    fileitem: FileItem


class ManualTransferItem(BaseModel):
    # 文件项
    fileitem: FileItem = None
    # 日志ID
    logid: Optional[int] = None
    # 目标存储
    target_storage: Optional[str] = None
    # 目标路径
    target_path: Optional[str] = None
    # TMDB ID
    tmdbid: Optional[int] = None
    # 豆瓣ID
    doubanid: Optional[str] = None
    # 类型
    type_name: Optional[str] = None
    # 季号
    season: Optional[int] = None
    # 整理方式
    transfer_type: Optional[str] = None
    # 自定义格式
    episode_format: Optional[str] = None
    # 指定集数
    episode_detail: Optional[str] = None
    # 指定PART
    episode_part: Optional[str] = None
    # 集数偏移
    episode_offset: Optional[str] = None
    # 最小文件大小
    min_filesize: Optional[int] = 0
    # 刮削
    scrape: bool = False
    # 媒体库类型子目录
    library_type_folder: Optional[bool] = None
    # 媒体库类别子目录
    library_category_folder: Optional[bool] = None
    # 复用历史识别信息
    from_history: Optional[bool] = False
    # 剧集组
    episode_group: Optional[str] = None
    # 仅预览，不执行整理
    preview: Optional[bool] = False
