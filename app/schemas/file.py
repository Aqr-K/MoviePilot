from typing import Optional

from pathlib import Path
from pydantic import BaseModel, Field
from app.schemas.types import StorageSchema


class FileURI(BaseModel):
    # 文件路径
    path: Optional[str] = "/"
    # 存储类型
    storage: Optional[str] = Field(default="local")

    @property
    def uri(self) -> str:
        return self.path if self.storage == "local" else f"{self.storage}:{self.path}"

    @classmethod
    def from_uri(cls, uri: str) -> "FileURI":
        storage, path = 'local', uri
        for s in StorageSchema:
            protocol = f"{s.value}:"
            if uri.startswith(protocol):
                path = uri[len(protocol):]
                storage = s.value
                break
        if not path.startswith("/"):
            path = "/" + path
        path = Path(path).as_posix()
        return cls(storage=storage, path=path)

class FileItem(FileURI):
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
    children: Optional[list] = Field(default_factory=list)
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
    # 总空间
    total: float = 0.0
    # 剩余空间
    available: float = 0.0


class StorageTransType(BaseModel):
    # 传输类型
    transtype: Optional[dict] = Field(default_factory=dict)

