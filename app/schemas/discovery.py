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
    # 数据源侧是否原生分页。放送表这类整份返回的固定内容为否，调用方据此得知结果集有界。
    # 与调用方能否翻页无关：所有榜单一律接受 page 与 count，源侧不原生分页时由源切片给出对应的一页
    paged: bool = Field(default=True)
