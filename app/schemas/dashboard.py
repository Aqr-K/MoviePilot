from typing import Optional

from pydantic import BaseModel, Field


class Statistic(BaseModel):
    """媒体库数量统计。"""

    # 电影
    movie_count: Optional[int] = 0
    # 电视剧数量
    tv_count: Optional[int] = 0
    # 集数量
    episode_count: Optional[int] = 0
    # 用户数量
    user_count: Optional[int] = 0
    # 本月新增电影数量
    movie_count_month: Optional[int] = 0
    # 本月新增电视剧数量
    tv_count_month: Optional[int] = 0
    # 本月新增剧集数量
    episode_count_month: Optional[int] = 0


class Storage(BaseModel):
    """仪表板存储空间统计。"""

    # 总存储空间
    total_storage: Optional[float] = 0.0
    # 已使用空间
    used_storage: Optional[float] = 0.0


class ProcessInfo(BaseModel):
    """仪表板进程运行信息。"""

    # 进程ID
    pid: Optional[int] = 0
    # 进程名称
    name: Optional[str] = None
    # 进程状态
    status: Optional[str] = None
    # 进程占用CPU
    cpu: Optional[float] = 0.0
    # 进程占用内存 MB
    memory: Optional[float] = 0.0
    # 进程创建时间
    create_time: Optional[float] = 0.0
    # 进程运行时间 秒
    run_time: Optional[float] = 0.0


class DownloaderInfo(BaseModel):
    """仪表板下载器汇总信息。"""

    # 下载速度
    download_speed: Optional[float] = 0.0
    # 上传速度
    upload_speed: Optional[float] = 0.0
    # 下载量
    download_size: Optional[float] = 0.0
    # 上传量
    upload_size: Optional[float] = 0.0
    # 剩余空间
    free_space: Optional[float] = 0.0


class DashboardMemoryInfo(BaseModel):
    """仪表板系统内存统计。"""

    # 总内存字节数
    total: int = 0
    # 已使用内存字节数，不包含缓存
    used: int = 0
    # 缓存与缓冲区占用字节数
    cached: int = 0
    # 可用内存字节数
    available: int = 0
    # 已使用内存占总内存百分比，不包含缓存
    usage: float = 0.0


class ScheduleProgress(BaseModel):
    """后台服务执行进度信息。"""

    # ID
    id: Optional[str] = None
    # 名称
    name: Optional[str] = None
    # 提供者
    provider: Optional[str] = None
    # 是否正在执行
    enable: Optional[bool] = False
    # 当前完成百分比
    value: Optional[float] = 0.0
    # 当前进度文本
    text: Optional[str] = None
    # 执行状态 waiting/running/success/failed
    status: Optional[str] = None
    # 最近一次执行是否成功
    success: Optional[bool] = None
    # 最近一次开始时间
    started_at: Optional[str] = None
    # 最近一次结束时间
    finished_at: Optional[str] = None
    # 最近一次错误信息
    error: Optional[str] = None
    # 扩展数据
    data: Optional[dict] = Field(default_factory=dict)


class ScheduleInfo(BaseModel):
    """仪表板后台服务信息。"""

    # ID
    id: Optional[str] = None
    # 名称
    name: Optional[str] = None
    # 提供者
    provider: Optional[str] = None
    # 状态
    status: Optional[str] = None
    # 下次执行时间
    next_run: Optional[str] = None
    # 当前完成百分比
    progress: Optional[float] = 0.0
    # 进度文本
    progress_text: Optional[str] = None
    # 是否正在更新进度
    progress_enable: Optional[bool] = False
    # 进度详情
    progress_detail: Optional[ScheduleProgress] = None


class DashboardSystemInfo(BaseModel):
    """仪表板系统摘要信息。"""

    # 主机名称
    hostname: str
    # 操作系统名称
    operating_system: str
    # MoviePilot 运行时间，单位秒
    runtime: int
    # MoviePilot 后端版本
    version: str
