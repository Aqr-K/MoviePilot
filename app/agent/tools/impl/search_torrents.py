"""搜索种子工具"""

import json
import re
from typing import List, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.search import SearchChain
from app.log import logger
from app.schemas.types import MediaType
from ._torrent_search_utils import (
    SEARCH_RESULT_CACHE_FILE,
    build_filter_options,
)


class SearchTorrentsInput(BaseModel):
    """搜索种子工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    title: str = Field(...,
                       description="The title of the media resource to search for (e.g., 'The Matrix 1999', 'Breaking Bad S01E01')")
    year: Optional[str] = Field(None,
                                description="Release year of the media (optional, helps narrow down search results)")
    media_type: Optional[str] = Field(None,
                                      description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None, description="Season number for TV shows (optional, only applicable for series)")
    sites: Optional[List[int]] = Field(None,
                                       description="Array of specific site IDs to search on (optional, if not provided searches all configured sites)")
    filter_pattern: Optional[str] = Field(None,
                                          description="Regular expression pattern to filter torrent titles by resolution, quality, or other keywords (e.g., '4K|2160p|UHD' for 4K content, '1080p|BluRay' for 1080p BluRay)")

class SearchTorrentsTool(MoviePilotTool):
    name: str = "search_torrents"
    description: str = "Search for torrent files across configured indexer sites based on media information. Returns available frontend-style filter options for the most recent search and caches the underlying results for get_search_results."
    args_schema: Type[BaseModel] = SearchTorrentsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据搜索参数生成友好的提示消息"""
        title = kwargs.get("title", "")
        year = kwargs.get("year")
        media_type = kwargs.get("media_type")
        season = kwargs.get("season")
        filter_pattern = kwargs.get("filter_pattern")
        
        message = f"正在搜索种子: {title}"
        if year:
            message += f" ({year})"
        if media_type:
            message += f" [{media_type}]"
        if season:
            message += f" 第{season}季"
        if filter_pattern:
            message += f" 过滤: {filter_pattern}"
        
        return message

    async def run(self, title: str, year: Optional[str] = None,
                  media_type: Optional[str] = None, season: Optional[int] = None,
                  sites: Optional[List[int]] = None, filter_pattern: Optional[str] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, sites={sites}, filter_pattern={filter_pattern}")

        try:
            search_chain = SearchChain()
            torrents = await search_chain.async_search_by_title(title=title, sites=sites)
            filtered_torrents = []
            # 编译正则表达式（如果提供）
            regex_pattern = None
            if filter_pattern:
                try:
                    regex_pattern = re.compile(filter_pattern, re.IGNORECASE)
                except re.error as e:
                    logger.warning(f"正则表达式编译失败: {filter_pattern}, 错误: {e}")
                    return f"正则表达式格式错误: {str(e)}"
            
            for torrent in torrents:
                # torrent 是 Context 对象，需要通过 meta_info 和 media_info 访问属性
                if year and torrent.meta_info and torrent.meta_info.year != year:
                    continue
                if media_type and torrent.meta_info and torrent.meta_info.type:
                    if torrent.meta_info.type != MediaType(media_type):
                        continue
                if season is not None and torrent.meta_info and torrent.meta_info.begin_season != season:
                    continue
                # 使用正则表达式过滤标题（分辨率、质量等关键字）
                if regex_pattern and torrent.torrent_info and torrent.torrent_info.title:
                    if not regex_pattern.search(torrent.torrent_info.title):
                        continue
                filtered_torrents.append(torrent)

            if filtered_torrents:
                await search_chain.async_save_cache(filtered_torrents, SEARCH_RESULT_CACHE_FILE)
                result_json = json.dumps({
                    "total_count": len(filtered_torrents),
                    "message": "搜索完成。请使用 get_search_results 工具获取搜索结果。",
                    "filter_options": build_filter_options(filtered_torrents),
                }, ensure_ascii=False, indent=2)
                return result_json
            else:
                return f"未找到相关种子资源: {title}"
        except Exception as e:
            error_message = f"搜索种子时发生错误: {str(e)}"
            logger.error(f"搜索种子失败: {e}", exc_info=True)
            return error_message
