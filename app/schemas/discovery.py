from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.types import MediaSource, MediaType


class DiscoverBoard(BaseModel):
    """一个发现榜单的声明。

    发现源经 ``discover_boards()`` 报出自己提供哪些榜单，调用方据此枚举，不必认识具体源。
    """

    # 榜单所属的数据来源
    source: MediaSource
    # 榜单标识，在同一来源内唯一，取榜单内容时按它定位
    board: str
    # 榜单显示名
    name: str
    # 榜单内容的媒体类型，混合内容时为空
    media_type: Optional[MediaType] = None
    # 是否支持翻页。放送表这类固定内容不支持，调用方据此决定是否展示翻页
    paged: bool = Field(default=True)
