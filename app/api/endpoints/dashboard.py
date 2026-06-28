from typing import Any, List, Optional, Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import schemas
from app.core.security import verify_apitoken
from app.db import get_db
from app.db.models.transferhistory import TransferHistory
from app.db.user_oper import get_current_active_superuser
from app.scheduler import Scheduler
from app.service.dashboard import (
    build_downloader as _build_downloader,
    build_statistic as _build_statistic,
    build_storage as _build_storage,
)
from app.utils.system import SystemUtils

router = APIRouter()


@router.get("/statistic", summary="媒体数量统计", response_model=schemas.Statistic)
def statistic(
    name: Optional[str] = None,
    db: Session = Depends(get_db),
    _: Any = Depends(get_current_active_superuser),
) -> Any:
    """
    查询媒体数量统计信息
    """
    return _build_statistic(db, name)


@router.get(
    "/statistic2", summary="媒体数量统计（API_TOKEN）", response_model=schemas.Statistic
)
def statistic2(
    _: Annotated[str, Depends(verify_apitoken)],
    db: Session = Depends(get_db),
) -> Any:
    """
    查询媒体数量统计信息 API_TOKEN认证（?token=xxx）
    """
    return _build_statistic(db)


@router.get("/storage", summary="本地存储空间", response_model=schemas.Storage)
def storage(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    查询本地存储空间信息
    """
    return _build_storage()


@router.get(
    "/storage2", summary="本地存储空间（API_TOKEN）", response_model=schemas.Storage
)
def storage2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    查询本地存储空间信息 API_TOKEN认证（?token=xxx）
    """
    return _build_storage()


@router.get("/processes", summary="进程信息", response_model=List[schemas.ProcessInfo])
def processes(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    查询进程信息
    """
    return SystemUtils.processes()


@router.get("/system", summary="系统摘要信息", response_model=schemas.DashboardSystemInfo)
def system_info(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    查询仪表板系统摘要信息
    """
    return SystemUtils.dashboard_system_info()


@router.get("/downloader", summary="下载器信息", response_model=schemas.DownloaderInfo)
def downloader(
    name: Optional[str] = None, _: Any = Depends(get_current_active_superuser)
) -> Any:
    """
    查询下载器信息
    """
    return _build_downloader(name)


@router.get(
    "/downloader2",
    summary="下载器信息（API_TOKEN）",
    response_model=schemas.DownloaderInfo,
)
def downloader2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    查询下载器信息 API_TOKEN认证（?token=xxx）
    """
    return _build_downloader()


@router.get("/schedule", summary="后台服务", response_model=List[schemas.ScheduleInfo])
async def schedule(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    查询后台服务信息
    """
    return Scheduler().list()


@router.get(
    "/schedule2",
    summary="后台服务（API_TOKEN）",
    response_model=List[schemas.ScheduleInfo],
)
async def schedule2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    查询下载器信息 API_TOKEN认证（?token=xxx）
    """
    return Scheduler().list()


@router.get("/transfer", summary="文件整理统计", response_model=List[int])
async def transfer(
    days: Optional[int] = 7,
    db: Session = Depends(get_db),
    _: Any = Depends(get_current_active_superuser),
) -> Any:
    """
    查询文件整理统计信息
    """
    transfer_stat = await TransferHistory.async_statistic(db, days)
    return [stat[1] for stat in transfer_stat]


@router.get("/cpu", summary="获取当前CPU使用率", response_model=float)
def cpu(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    获取当前CPU使用率
    """
    return SystemUtils.cpu_usage()


@router.get("/cpu2", summary="获取当前CPU使用率（API_TOKEN）", response_model=float)
def cpu2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    获取当前CPU使用率 API_TOKEN认证（?token=xxx）
    """
    return SystemUtils.cpu_usage()


@router.get("/memory", summary="获取当前内存使用量和使用率", response_model=List[int])
def memory(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    获取当前内存使用率
    """
    return SystemUtils.memory_usage()


@router.get(
    "/memory2",
    summary="获取当前内存使用量和使用率（API_TOKEN）",
    response_model=List[int],
)
def memory2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    获取当前内存使用率 API_TOKEN认证（?token=xxx）
    """
    return SystemUtils.memory_usage()


@router.get("/network", summary="获取当前网络流量", response_model=List[int])
def network(_: Any = Depends(get_current_active_superuser)) -> Any:
    """
    获取当前网络流量（上行和下行流量，单位：bytes/s）
    """
    return SystemUtils.network_usage()


@router.get(
    "/network2", summary="获取当前网络流量（API_TOKEN）", response_model=List[int]
)
def network2(_: Annotated[str, Depends(verify_apitoken)]) -> Any:
    """
    获取当前网络流量 API_TOKEN认证（?token=xxx）
    """
    return SystemUtils.network_usage()
