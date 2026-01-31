"""搜索种子工具"""

import json
import re
from typing import List, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.search import SearchChain
from app.log import logger
from app.schemas.types import MediaType
from app.utils.string import StringUtils


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
    description: str = "Search for torrent files across configured indexer sites based on media information. Returns available torrent downloads with details like file size, quality, and download links."
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
                if media_type and torrent.media_info:
                    if torrent.media_info.type != MediaType(media_type):
                        continue
                if season is not None and torrent.meta_info and torrent.meta_info.begin_season != season:
                    continue
                # 使用正则表达式过滤标题（分辨率、质量等关键字）
                if regex_pattern and torrent.torrent_info and torrent.torrent_info.title:
                    if not regex_pattern.search(torrent.torrent_info.title):
                        continue
                filtered_torrents.append(torrent)

            if filtered_torrents:
                # 限制最多50条结果
                total_count = len(filtered_torrents)
                limited_torrents = filtered_torrents[:50]
                # 精简字段，只保留关键信息
                simplified_torrents = []
                for t in limited_torrents:
                    simplified = {}
                    # 精简 torrent_info
                    if t.torrent_info:
                        simplified["torrent_info"] = {
                            "title": t.torrent_info.title,
                            "size": StringUtils.format_size(t.torrent_info.size),
                            "seeders": t.torrent_info.seeders,
                            "peers": t.torrent_info.peers,
                            "site_name": t.torrent_info.site_name,
                            "enclosure": t.torrent_info.enclosure,
                            "page_url": t.torrent_info.page_url,
                            "volume_factor": t.torrent_info.volume_factor,
                            "pubdate": t.torrent_info.pubdate
                        }
                    # 精简 media_info
                    if t.media_info:
                        simplified["media_info"] = {
                            "title": t.media_info.title,
                            "en_title": t.media_info.en_title,
                            "year": t.media_info.year,
                            "type": t.media_info.type.value if t.media_info.type else None,
                            "season": t.media_info.season,
                            "tmdb_id": t.media_info.tmdb_id
                        }
                    # 精简 meta_info
                    if t.meta_info:
                        simplified["meta_info"] = {
                            "name": t.meta_info.name,
                            "cn_name": t.meta_info.cn_name,
                            "en_name": t.meta_info.en_name,
                            "year": t.meta_info.year,
                            "type": t.meta_info.type.value if t.meta_info.type else None,
                            "begin_season": t.meta_info.begin_season
                        }
                    simplified_torrents.append(simplified)
                result_json = json.dumps(simplified_torrents, ensure_ascii=False, indent=2)
                # 如果结果被裁剪，添加提示信息
                if total_count > 50:
                    return f"注意：搜索结果共找到 {total_count} 条，为节省上下文空间，仅显示前 50 条结果。\n\n{result_json}"
                return result_json
            else:
                return f"未找到相关种子资源: {title}"
        except Exception as e:
            error_message = f"搜索种子时发生错误: {str(e)}"
            logger.error(f"搜索种子失败: {e}", exc_info=True)
            return error_message
