from pathlib import Path

from app.core.context import MediaInfo
from app.core.metainfo import MetaInfoPath
from app.modules.filemanager import FileManagerModule
from app.schemas import FileItem, TransferDirectoryConf
from app.schemas.types import MediaType


class GuardedStorage:
    """
    用于验证预览模式不会访问可能有副作用的存储整理接口。
    """

    def get_folder(self, path: Path):  # pragma: no cover - 被调用即失败
        raise AssertionError(f"预览不应创建或获取目标目录：{path}")

    def get_item(self, path: Path):  # pragma: no cover - 被调用即失败
        raise AssertionError(f"预览不应探测目标文件：{path}")

    def copy(self, *args, **kwargs):  # pragma: no cover - 被调用即失败
        raise AssertionError("预览不应复制文件")

    def move(self, *args, **kwargs):  # pragma: no cover - 被调用即失败
        raise AssertionError("预览不应移动文件")

    def rename(self, *args, **kwargs):  # pragma: no cover - 被调用即失败
        raise AssertionError("预览不应重命名文件")

    def delete(self, *args, **kwargs):  # pragma: no cover - 被调用即失败
        raise AssertionError("预览不应删除文件")


def test_cloud_storage_preview_only_calculates_target_path():
    fileitem = FileItem(
        storage="alist",
        path="/downloads/Test.Show.S01E01.mkv",
        type="file",
        name="Test.Show.S01E01.mkv",
        basename="Test.Show.S01E01",
        extension="mkv",
        size=1024,
    )
    meta = MetaInfoPath(Path(fileitem.path))
    mediainfo = MediaInfo(
        type=MediaType.TV,
        title="Test Show",
        year="2026",
        tmdb_id=12345,
    )
    target_directory = TransferDirectoryConf(
        name="cloud-library",
        transfer_type="copy",
        overwrite_mode="latest",
        library_path="/library",
        library_storage="alist",
        renaming=True,
        scraping=True,
        notify=True,
    )
    guarded_storage = GuardedStorage()

    transferinfo = FileManagerModule().transfer(
        fileitem=fileitem,
        meta=meta,
        mediainfo=mediainfo,
        target_directory=target_directory,
        source_oper=guarded_storage,
        target_oper=guarded_storage,
        preview=True,
    )

    assert transferinfo.success is True
    assert transferinfo.need_notify is False
    assert transferinfo.need_scrape is True
    assert transferinfo.target_item.storage == "alist"
    assert transferinfo.target_item.path.endswith(".mkv")
    assert transferinfo.target_diritem.path.startswith("/library/")
    assert transferinfo.file_list == [fileitem.path]
    assert transferinfo.file_list_new == [transferinfo.target_item.path]


def test_local_storage_preview_skips_target_conflict_checks(tmp_path):
    source_file = tmp_path / "downloads" / "Test.Show.S01E02.mkv"
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"test video")
    library_path = tmp_path / "library"
    fileitem = FileItem(
        storage="local",
        path=source_file.as_posix(),
        type="file",
        name=source_file.name,
        basename=source_file.stem,
        extension="mkv",
        size=source_file.stat().st_size,
    )
    meta = MetaInfoPath(source_file)
    mediainfo = MediaInfo(
        type=MediaType.TV,
        title="Test Show",
        year="2026",
        tmdb_id=12345,
    )
    target_directory = TransferDirectoryConf(
        name="local-library",
        transfer_type="copy",
        overwrite_mode="latest",
        library_path=library_path.as_posix(),
        library_storage="local",
        renaming=True,
        scraping=True,
        notify=True,
    )
    guarded_storage = GuardedStorage()

    transferinfo = FileManagerModule().transfer(
        fileitem=fileitem,
        meta=meta,
        mediainfo=mediainfo,
        target_directory=target_directory,
        source_oper=guarded_storage,
        target_oper=guarded_storage,
        preview=True,
    )

    assert transferinfo.success is True
    assert transferinfo.need_notify is False
    assert transferinfo.need_scrape is True
    assert transferinfo.target_item.storage == "local"
    assert transferinfo.target_item.path.startswith(library_path.as_posix())
    assert transferinfo.target_item.path.endswith(".mkv")
    assert transferinfo.file_list == [fileitem.path]
    assert transferinfo.file_list_new == [transferinfo.target_item.path]
