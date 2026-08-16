"""本地媒体库文件检索。

``media_files`` 按命名模板算出媒体在库中的落点，再列举该目录下的文件；``media_exists``
据此判断媒体是否已存在于本地库，影响订阅完成判定与查重。

存储升为一级模块后，递归列举移到了调用方，驱动只提供单层 ``list``。这里锁住两件事：
目录内容能被完整取回（含子目录里的文件），以及取不到时返回空而不是抛错。
"""
from pathlib import Path
from typing import List, Optional
from unittest.mock import Mock, patch

import pytest

from app import schemas
from app.application.transfer.handler import TransHandler
from app.schemas.types import MediaType


def file_item(path: str, extension: str) -> schemas.FileItem:
    """
    构造文件项

    :param path: 文件路径
    :param extension: 扩展名
    :return: 文件项
    """
    return schemas.FileItem(storage="local", path=path, type="file",
                            name=Path(path).name, basename=Path(path).stem,
                            extension=extension)


def dir_item(path: str) -> schemas.FileItem:
    """
    构造目录项

    :param path: 目录路径
    :return: 目录项
    """
    return schemas.FileItem(storage="local", path=path, type="dir", name=Path(path).name)


class StubStorage:
    """只提供单层列举的存储替身"""

    def __init__(self, listings: dict):
        """
        :param listings: {目录路径: [子项, ...]}
        """
        self.listings = listings

    def get_item(self, path: Path) -> Optional[schemas.FileItem]:
        """按路径取项"""
        return dir_item(path.as_posix())

    def list(self, fileitem: schemas.FileItem) -> List[schemas.FileItem]:
        """单层列举"""
        return self.listings.get(fileitem.path, [])


@pytest.fixture
def library_dir() -> Mock:
    """构造一个启用整理的媒体库目录配置。"""
    directory = Mock()
    directory.library_storage = "local"
    directory.library_path = "/media"
    directory.media_type = None
    directory.media_category = None
    return directory


def scan(listings: dict, library_dir: Mock) -> List[schemas.FileItem]:
    """
    在打桩的目录配置与存储下执行媒体库检索

    :param listings: 存储的单层列举结果
    :param library_dir: 媒体库目录配置
    :return: 检索到的文件项
    """
    mediainfo = Mock()
    mediainfo.type = MediaType.MOVIE
    mediainfo.title_year = "示例电影 (2024)"
    handler = TransHandler()
    root = Path("/media/电影/示例电影 (2024)")
    with patch("app.application.transfer.handler.DirectoryHelper") as helper, \
            patch("app.application.transfer.handler.get_storage",
                  return_value=StubStorage(listings)), \
            patch("app.application.transfer.handler.settings") as stub_settings, \
            patch.object(TransHandler, "get_dest_dir", return_value=Path("/media/电影")), \
            patch.object(TransHandler, "get_rename_path", return_value=root), \
            patch.object(TransHandler, "get_naming_dict", return_value={}), \
            patch.object(TransHandler, "_build_library_lookup_meta", return_value=Mock()):
        stub_settings.RENAME_FORMAT.return_value = "{{title}}"
        stub_settings.RMT_MEDIAEXT = [".mkv", ".m2ts"]
        stub_settings.RMT_AUDIOEXT = [".flac"]
        helper.return_value.get_library_dirs.return_value = [library_dir]
        helper.get_media_root_path.return_value = root
        return handler.media_files(mediainfo)


def test_files_in_the_library_directory_are_found(library_dir):
    """媒体库目录下的文件能被取回。"""
    movie = file_item("/media/电影/示例电影 (2024)/示例电影.mkv", "mkv")

    found = scan({"/media/电影/示例电影 (2024)": [movie]}, library_dir)

    assert [item.path for item in found] == [movie.path]


def test_files_nested_in_subdirectories_are_found(library_dir):
    """子目录里的文件同样能被取回，驱动只提供单层列举，递归由调用方完成。"""
    subdir = dir_item("/media/电影/示例电影 (2024)/BDMV")
    nested = file_item("/media/电影/示例电影 (2024)/BDMV/main.m2ts", "m2ts")

    found = scan({
        "/media/电影/示例电影 (2024)": [subdir],
        "/media/电影/示例电影 (2024)/BDMV": [nested],
    }, library_dir)

    assert [item.path for item in found] == [nested.path]


def test_an_empty_library_directory_yields_nothing(library_dir):
    """目录为空时返回空列表，不抛错。"""
    assert scan({"/media/电影/示例电影 (2024)": []}, library_dir) == []
