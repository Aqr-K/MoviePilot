"""搜索种子工具"""

import json
from typing import List, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.search import SearchChain
from app.db.systemconfig_oper import SystemConfigOper
from app.helper.sites import SitesHelper
from app.log import logger
from app.schemas.types import MediaType, SystemConfigKey
from ._torrent_search_utils import (
    SEARCH_RESULT_CACHE_FILE,
    build_filter_options,
)


class SearchTorrentsInput(BaseModel):
    """搜索种子工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    tmdb_id: Optional[int] = Field(None, description="TMDB ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    douban_id: Optional[str] = Field(None, description="Douban ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    media_type: Optional[str] = Field(None, description="Allowed values: movie, tv")
    area: Optional[str] = Field(None, description="Search scope: 'title' (default) or 'imdbid'")
    sites: Optional[List[int]] = Field(None,
                                       description="Array of specific site IDs to search on (optional, if not provided searches all configured sites)")

class SearchTorrentsTool(MoviePilotTool):
    name: str = "search_torrents"
    description: str = ("Search for torrent files by media ID across configured indexer sites, cache the matched results, "
                        "and return available filter options for follow-up selection. "
                        "Requires tmdb_id or douban_id (can be obtained from search_media tool) for accurate matching.")
    args_schema: Type[BaseModel] = SearchTorrentsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据搜索参数生成友好的提示消息"""
        tmdb_id = kwargs.get("tmdb_id")
        douban_id = kwargs.get("douban_id")
        media_type = kwargs.get("media_type")

        if tmdb_id:
            message = f"正在搜索种子: TMDB={tmdb_id}"
        elif douban_id:
            message = f"正在搜索种子: 豆瓣={douban_id}"
        else:
            message = "正在搜索种子"
        if media_type:
            message += f" [{media_type}]"
        return message

    async def run(self, tmdb_id: Optional[int] = None, douban_id: Optional[str] = None,
                  media_type: Optional[str] = None, area: Optional[str] = None,
                  sites: Optional[List[int]] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: tmdb_id={tmdb_id}, douban_id={douban_id}, media_type={media_type}, area={area}, sites={sites}")

        if not tmdb_id and not douban_id:
            return "参数错误：tmdb_id 和 douban_id 至少需要提供一个，请先使用 search_media 工具获取媒体 ID。"

        try:
            search_chain = SearchChain()
            media_type_enum = None
            if media_type:
                media_type_key = media_type.strip().lower()
                if media_type_key == "movie":
                    media_type_enum = MediaType.MOVIE
                elif media_type_key == "tv":
                    media_type_enum = MediaType.TV
                else:
                    return f"错误：无效的媒体类型 '{media_type}'，支持的类型：'movie', 'tv'"

            filtered_torrents = await search_chain.async_search_by_id(
                tmdbid=tmdb_id,
                doubanid=douban_id,
                mtype=media_type_enum,
                area=area or "title",
                sites=sites,
                cache_local=False,
            )

            # 获取站点信息
            all_indexers = await SitesHelper().async_get_indexers()
            all_sites = [{"id": indexer.get("id"), "name": indexer.get("name")} for indexer in (all_indexers or [])]

            if sites:
                search_site_ids = sites
            else:
                configured_sites = SystemConfigOper().get(SystemConfigKey.IndexerSites)
                search_site_ids = configured_sites if configured_sites else []

            if filtered_torrents:
                await search_chain.async_save_cache(filtered_torrents, SEARCH_RESULT_CACHE_FILE)
                result_json = json.dumps({
                    "total_count": len(filtered_torrents),
                    "message": "搜索完成。请使用 get_search_results 工具获取搜索结果。",
                    "all_sites": all_sites,
                    "search_site_ids": search_site_ids,
                    "filter_options": build_filter_options(filtered_torrents),
                }, ensure_ascii=False, indent=2)
                return result_json
            else:
                media_id = f"TMDB={tmdb_id}" if tmdb_id else f"豆瓣={douban_id}"
                result_json = json.dumps({
                    "message": f"未找到相关种子资源: {media_id}",
                    "all_sites": all_sites,
                    "search_site_ids": search_site_ids,
                }, ensure_ascii=False, indent=2)
                return result_json
        except Exception as e:
            error_message = f"搜索种子时发生错误: {str(e)}"
            logger.error(f"搜索种子失败: {e}", exc_info=True)
            return error_message
