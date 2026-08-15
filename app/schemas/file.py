import re
from typing import Callable, Iterable, List, Optional

from pathlib import Path
from pydantic import BaseModel, Field
from app.schemas.types import StorageSchema

# Windows 盘符绝对路径，如 Z:/Downloads 或 Z:\Downloads
WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")

# 内建之外的存储标识来源，由存储层装配；未装配时只认内建存储
_extra_schema_provider: Optional[Callable[[], Iterable[str]]] = None


def configure_storage_schema_provider(provider: Optional[Callable[[], Iterable[str]]]) -> None:
    """
    装配内建之外的存储标识来源，使 URI 解析能认出外部注册的存储

    :param provider: 返回存储标识集合的可调用对象，传 None 时只认内建存储
    """
    global _extra_schema_provider
    _extra_schema_provider = provider


def known_storage_schemas() -> List[str]:
    """
    列出当前可被 URI 前缀识别的全部存储标识

    :return: 内建存储标识，以及外部来源注册的存储标识
    """
    schemas = [schema.value for schema in StorageSchema]
    if _extra_schema_provider is None:
        return schemas
    try:
        extra = list(_extra_schema_provider() or [])
    except Exception:
        return schemas
    return schemas + [schema for schema in extra if schema and schema not in schemas]


class FileURI(BaseModel):
    """带存储类型的文件 URI。"""

    # 文件路径
    path: Optional[str] = "/"
    # 存储类型
    storage: Optional[str] = Field(default="local")

    @property
    def uri(self) -> str:
        """
        文件 URI，本地存储直接返回路径，其他存储带上存储前缀
        """
        return self.path if self.storage == "local" else f"{self.storage}:{self.path}"

    @classmethod
    def from_uri(cls, uri: str) -> "FileURI":
        """
        解析文件 URI 为存储类型和路径

        :param uri: 文件 URI，如 /media/movie、u115:/media/movie 或 Windows 盘符路径 Z:/media
        :return: FileURI 对象
        """
        storage, path = 'local', uri
        for schema in known_storage_schemas():
            protocol = f"{schema}:"
            if uri.startswith(protocol):
                path = uri[len(protocol):]
                storage = schema
                break
        # Windows 盘符路径本身就是绝对路径，补上根斜杠会得到 /Z:/xxx 这样的非法路径
        if not path.startswith("/") and not WINDOWS_DRIVE_PATTERN.match(path):
            path = "/" + path
        path = Path(path).as_posix()
        return cls(storage=storage, path=path)


class FileItem(FileURI):
    """文件或目录条目，目录可递归包含子条目。"""

    # 类型 dir/file
    type: Optional[str] = None
    # 文件名
    name: Optional[str] = None
    # 文件名
    basename: Optional[str] = None
    # 文件后缀
    extension: Optional[str] = None
    # 文件大小
    size: Optional[int] = None
    # 修改时间
    modify_time: Optional[float] = None
    # 子节点
    children: Optional[list["FileItem"]] = Field(default_factory=list)
    # ID
    fileid: Optional[str] = None
    # 父ID
    parent_fileid: Optional[str] = None
    # 缩略图
    thumbnail: Optional[str] = None
    # 115 pickcode
    pickcode: Optional[str] = None
    # drive_id
    drive_id: Optional[str] = None
    # url
    url: Optional[str] = None


class StorageUsage(BaseModel):
    """存储空间使用情况。"""

    # 总空间
    total: float = 0.0
    # 剩余空间
    available: float = 0.0


class StorageTransType(BaseModel):
    """存储支持的传输类型及其显示名称。"""

    # 传输类型
    transtype: Optional[dict[str, str]] = Field(default_factory=dict)
