"""搜索种子工具"""

import json
from typing import List, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.search import SearchChain
from app.log import logger
from app.schemas.types import MediaType


class SearchTorrentsInput(BaseModel):
    """搜索种子工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    title: str = Field(..., description="The title of the media resource to search for (e.g., 'The Matrix 1999', 'Breaking Bad S01E01')")
    year: Optional[str] = Field(None, description="Release year of the media (optional, helps narrow down search results)")
    media_type: Optional[str] = Field(None, description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None, description="Season number for TV shows (optional, only applicable for series)")
    sites: Optional[List[int]] = Field(None, description="Array of specific site IDs to search on (optional, if not provided searches all configured sites)")


class SearchTorrentsTool(MoviePilotTool):
    name: str = "search_torrents"
    description: str = "Search for torrent files across configured indexer sites based on media information. Returns available torrent downloads with details like file size, quality, and download links."
    args_schema: Type[BaseModel] = SearchTorrentsInput

    async def _arun(self, title: str, year: Optional[str] = None,
                    media_type: Optional[str] = None, season: Optional[int] = None,
                    sites: Optional[List[int]] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, sites={sites}")

        # 发送工具执行说明
        self.send_tool_message(f"正在搜索种子资源: {title}" + (f" ({year})" if year else ""), title="搜索种子")

        try:
            search_chain = SearchChain()
            torrents = search_chain.search_by_title(title=title, sites=sites)
            filtered_torrents = []
            for torrent in torrents:
                # torrent 是 Context 对象，需要通过 meta_info 和 media_info 访问属性
                if year and torrent.meta_info and torrent.meta_info.year != year:
                    continue
                if media_type and torrent.media_info:
                    if torrent.media_info.type != MediaType(media_type):
                        continue
                if season and torrent.meta_info and torrent.meta_info.begin_season != season:
                    continue
                filtered_torrents.append(torrent)

            if filtered_torrents:
                result_message = f"找到 {len(filtered_torrents)} 个相关种子资源"
                self.send_tool_message(result_message, title="搜索成功")

                # 发送详细结果
                for i, torrent in enumerate(filtered_torrents[:5]):  # 只显示前5个结果
                    torrent_title = torrent.torrent_info.title if torrent.torrent_info else torrent.meta_info.title if torrent.meta_info else "未知"
                    site_name = torrent.torrent_info.site_name if torrent.torrent_info else "未知站点"
                    torrent_info = f"{i + 1}. {torrent_title} - {site_name}"
                    self.send_tool_message(torrent_info, title="搜索结果")

                return json.dumps([t.to_dict() for t in filtered_torrents], ensure_ascii=False, indent=2)
            else:
                error_message = f"未找到相关种子资源: {title}"
                self.send_tool_message(error_message, title="搜索完成")
                return error_message
        except Exception as e:
            error_message = f"搜索种子时发生错误: {str(e)}"
            logger.error(f"搜索种子失败: {e}", exc_info=True)
            self.send_tool_message(error_message, title="搜索失败")
            return error_message
