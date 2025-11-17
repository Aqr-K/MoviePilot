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
    title: str = Field(...,
                       description="The title of the media resource to search for (e.g., 'The Matrix 1999', 'Breaking Bad S01E01')")
    year: Optional[str] = Field(None,
                                description="Release year of the media (optional, helps narrow down search results)")
    media_type: Optional[str] = Field(None,
                                      description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None, description="Season number for TV shows (optional, only applicable for series)")
    sites: Optional[List[int]] = Field(None,
                                       description="Array of specific site IDs to search on (optional, if not provided searches all configured sites)")


class SearchTorrentsTool(MoviePilotTool):
    name: str = "search_torrents"
    description: str = "Search for torrent files across configured indexer sites based on media information. Returns available torrent downloads with details like file size, quality, and download links."
    args_schema: Type[BaseModel] = SearchTorrentsInput

    async def run(self, title: str, year: Optional[str] = None,
                  media_type: Optional[str] = None, season: Optional[int] = None,
                  sites: Optional[List[int]] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, sites={sites}")

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
                            "size": t.torrent_info.size,
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
