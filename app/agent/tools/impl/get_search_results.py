"""获取搜索结果工具"""

import json
from typing import List, Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.search import SearchChain
from app.log import logger
from ._torrent_search_utils import (
    TORRENT_RESULT_LIMIT,
    filter_contexts,
    simplify_search_result,
)


class GetSearchResultsInput(BaseModel):
    """获取搜索结果工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    site: Optional[List[str]] = Field(None, description="Filter by site name, supports multiple values")
    season: Optional[List[str]] = Field(None, description="Filter by season/episode label, supports multiple values")
    free_state: Optional[List[str]] = Field(None, description="Filter by promotion state, supports multiple values")
    video_code: Optional[List[str]] = Field(None, description="Filter by video codec, supports multiple values")
    edition: Optional[List[str]] = Field(None, description="Filter by edition/quality, supports multiple values")
    resolution: Optional[List[str]] = Field(None, description="Filter by resolution, supports multiple values")
    release_group: Optional[List[str]] = Field(None, description="Filter by release group, supports multiple values")

class GetSearchResultsTool(MoviePilotTool):
    name: str = "get_search_results"
    description: str = "Get torrent search results from the most recent search_torrents call, with optional frontend-style filters such as site, season, promotion state, codec, quality, resolution, and release group. Returns at most the first 50 matching results."
    args_schema: Type[BaseModel] = GetSearchResultsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        return "正在获取搜索结果"

    async def run(self, site: Optional[List[str]] = None, season: Optional[List[str]] = None,
                  free_state: Optional[List[str]] = None, video_code: Optional[List[str]] = None,
                  edition: Optional[List[str]] = None, resolution: Optional[List[str]] = None,
                  release_group: Optional[List[str]] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: site={site}, season={season}, free_state={free_state}, video_code={video_code}, edition={edition}, resolution={resolution}, release_group={release_group}")

        try:
            items = await SearchChain().async_last_search_results() or []
            if not items:
                return "没有可用的搜索结果，请先使用 search_torrents 搜索"

            filtered_items = filter_contexts(
                items=items,
                site=site,
                season=season,
                free_state=free_state,
                video_code=video_code,
                edition=edition,
                resolution=resolution,
                release_group=release_group,
            )
            if not filtered_items:
                return "没有符合筛选条件的搜索结果，请调整筛选条件"

            total_count = len(filtered_items)
            filtered_ids = {id(item) for item in filtered_items}
            matched_indices = [index for index, item in enumerate(items, start=1) if id(item) in filtered_ids]
            limited_items = filtered_items[:TORRENT_RESULT_LIMIT]
            limited_indices = matched_indices[:TORRENT_RESULT_LIMIT]
            results = [
                simplify_search_result(item, index)
                for item, index in zip(limited_items, limited_indices)
            ]
            payload = {
                "total_count": total_count,
                "results": results,
            }
            if total_count > TORRENT_RESULT_LIMIT:
                payload["message"] = f"搜索结果共找到 {total_count} 条，仅显示前 {TORRENT_RESULT_LIMIT} 条结果。"
            return json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception as e:
            error_message = f"获取搜索结果失败: {str(e)}"
            logger.error(f"获取搜索结果失败: {e}", exc_info=True)
            return error_message
