from typing import Any, List, Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Body

from app import schemas
from app.chain.download import DownloadChain
from app.core.context import SubtitleInfo
from app.core.security import verify_token
from app.db.models.user import User
from app.db.systemconfig_oper import SystemConfigOper
from app.db.user_oper import get_current_active_user
from app.helper.directory import DirectoryHelper
from app.schemas.types import SystemConfigKey
from app.service.download import (
    add_download_with_media as _add_download_with_media,
    prepare_subtitle_download as _prepare_subtitle_download,
    recognize_and_download as _recognize_and_download,
)

router = APIRouter()
MediaSource = Literal["themoviedb", "douban", "bangumi", "anilist"]


@router.get("/", summary="正在下载", response_model=List[schemas.DownloaderTorrent])
def current(
    name: Optional[str] = None, _: schemas.TokenPayload = Depends(verify_token)
) -> Any:
    """
    查询正在下载的任务
    """
    return DownloadChain().downloading(name)


@router.post("/", summary="添加下载（含媒体信息）", response_model=schemas.Response)
def download(
    media_in: schemas.MediaInfo,
    torrent_in: schemas.TorrentInfo,
    downloader: Annotated[str | None, Body()] = None,
    save_path: Annotated[str | None, Body()] = None,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    添加下载任务（含媒体信息）
    """
    did = _add_download_with_media(
        media_in=media_in,
        torrent_in=torrent_in,
        downloader=downloader,
        save_path=save_path,
        username=current_user.name,
    )
    if not did:
        return schemas.Response(success=False, message="任务添加失败")
    return schemas.Response(success=True, data={"download_id": did})


@router.post(
    "/add", summary="添加下载（不含媒体信息）", response_model=schemas.Response
)
def add(
    torrent_in: schemas.TorrentInfo,
    tmdbid: Annotated[int | None, Body()] = None,
    doubanid: Annotated[str | None, Body()] = None,
    media_source: Annotated[MediaSource | None, Body()] = None,
    media_id: Annotated[str | None, Body()] = None,
    downloader: Annotated[str | None, Body()] = None,
    # 保存路径, 支持<storage>:<path>, 如rclone:/MP, smb:/server/share/Movies等
    save_path: Annotated[str | None, Body()] = None,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    添加下载任务（不含媒体信息）
    """
    recognized, did = _recognize_and_download(
        torrent_in=torrent_in,
        tmdbid=tmdbid,
        doubanid=doubanid,
        media_source=media_source,
        media_id=media_id,
        downloader=downloader,
        save_path=save_path,
        username=current_user.name,
    )
    if not recognized:
        return schemas.Response(success=False, message="无法识别媒体信息")
    if not did:
        return schemas.Response(success=False, message="任务添加失败")
    return schemas.Response(success=True, data={"download_id": did})


@router.post("/subtitle", summary="下载字幕", response_model=schemas.Response)
def download_subtitle(
    subtitle_in: schemas.SubtitleInfo,
    tmdbid: Annotated[int | None, Body()] = None,
    doubanid: Annotated[str | None, Body()] = None,
    media_source: Annotated[MediaSource | None, Body()] = None,
    media_id: Annotated[str | None, Body()] = None,
    save_path: Annotated[str | None, Body()] = None,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    下载字幕资源。
    """
    subtitle_info = SubtitleInfo()
    subtitle_info.from_dict(subtitle_in.model_dump())
    valid, message = _prepare_subtitle_download(subtitle_info)
    if not valid:
        return schemas.Response(success=False, message=message)

    success, message, saved_files = DownloadChain().download_subtitle(
        subtitle=subtitle_info,
        media_source=media_source,
        media_id=media_id,
        tmdbid=tmdbid,
        doubanid=doubanid,
        save_path=save_path,
        username=current_user.name,
    )
    return schemas.Response(
        success=success,
        message=message,
        data={"files": saved_files} if saved_files else None,
    )


@router.get("/start/{hashString}", summary="开始任务", response_model=schemas.Response)
def start(
    hashString: str,
    name: Optional[str] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    开如下载任务
    """
    ret = DownloadChain().set_downloading(hashString, "start", name=name)
    return schemas.Response(success=True if ret else False)


@router.get("/stop/{hashString}", summary="暂停任务", response_model=schemas.Response)
def stop(
    hashString: str,
    name: Optional[str] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    暂停下载任务
    """
    ret = DownloadChain().set_downloading(hashString, "stop", name=name)
    return schemas.Response(success=True if ret else False)


@router.get("/clients", summary="查询可用下载器", response_model=List[dict])
async def clients(_: schemas.TokenPayload = Depends(verify_token)) -> Any:
    """
    查询可用下载器
    """
    downloaders: List[dict] = SystemConfigOper().get(SystemConfigKey.Downloaders)
    if downloaders:
        return [
            {"name": d.get("name"), "type": d.get("type")}
            for d in downloaders
            if d.get("enabled")
        ]
    return []


@router.get(
    "/paths", summary="查询可用下载路径", response_model=List[schemas.DownloadDirectory]
)
def paths(_: schemas.TokenPayload = Depends(verify_token)) -> Any:
    """
    查询可直接用于下载接口 save_path 参数的下载路径
    """
    return [
        schemas.DownloadDirectory(
            name=dir_info.name,
            storage=dir_info.storage or "local",
            download_path=dir_info.download_path,
            save_path=schemas.FileURI(
                storage=dir_info.storage or "local",
                path=dir_info.download_path,
            ).uri,
            priority=dir_info.priority,
            media_type=dir_info.media_type,
            media_category=dir_info.media_category,
        )
        for dir_info in DirectoryHelper().get_download_dirs()
        if dir_info.download_path
    ]


@router.delete("/{hashString}", summary="删除下载任务", response_model=schemas.Response)
def delete(
    hashString: str,
    name: Optional[str] = None,
    _: schemas.TokenPayload = Depends(verify_token),
) -> Any:
    """
    删除下载任务
    """
    ret = DownloadChain().remove_downloading(hashString, name=name)
    return schemas.Response(success=True if ret else False)
