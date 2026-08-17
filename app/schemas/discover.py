"""发现榜单的声明。

榜单与「条件发现」不同：条件发现是同一个能力换一组参数，榜单则是一组**语义各异**的
能力——本周放送表、固定的 Top250、实时趋势，彼此不可通约。因此它需要两个契约而不是
一个：先由各源交出自己有哪些榜单，再按标识去取某一个。

分页正是不可通约之处：豆瓣七个榜单都支持 (page, count)，TMDB 趋势只有 page，Bangumi
放送表干脆没有分页。若不声明，前端翻页会打到不支持分页的源上。paginated 就是为此存在。
"""
from typing import Optional

from pydantic import BaseModel, Field


class DiscoverBoard(BaseModel):
    """一个可枚举的发现榜单"""

    # 提供该榜单的数据源
    source: str
    # 榜单标识，同一数据源内唯一，用于回头取这个榜单
    board: str
    # 榜单显示名
    name: str
    # 榜单内容的媒体类型，混合或未知时为空
    media_type: Optional[str] = None
    # 是否支持分页。不支持时调用方不应传页码，源也不会分页返回
    paginated: bool = Field(default=True)
