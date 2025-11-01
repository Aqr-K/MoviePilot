"""搜索媒体工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.media import MediaChain
from app.log import logger
from app.schemas.types import MediaType


class SearchMediaInput(BaseModel):
    """搜索媒体工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    title: str = Field(..., description="The title of the media to search for (e.g., 'The Matrix', 'Breaking Bad')")
    year: Optional[str] = Field(None, description="Release year of the media (optional, helps narrow down results)")
    media_type: Optional[str] = Field(None, description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None, description="Season number for TV shows and anime (optional, only applicable for series)")


class SearchMediaTool(MoviePilotTool):
    name: str = "search_media"
    description: str = "Search for media resources including movies, TV shows, anime, etc. Supports searching by title, year, type, and other criteria. Returns detailed media information from TMDB database."
    args_schema: Type[BaseModel] = SearchMediaInput

    async def _arun(self, title: str, year: Optional[str] = None,
                    media_type: Optional[str] = None, season: Optional[int] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}")

        # 发送工具执行说明
        self.send_tool_message(f"正在搜索媒体资源: {title}" + (f" ({year})" if year else ""), title="搜索中")

        try:
            media_chain = MediaChain()
            # 构建搜索标题
            search_title = title
            if year:
                search_title = f"{title} {year}"
            if media_type:
                search_title = f"{search_title} {media_type}"
            if season:
                search_title = f"{search_title} S{season:02d}"

            # 使用 MediaChain.search 方法
            meta, results = media_chain.search(title=search_title)

            # 过滤结果
            if results:
                filtered_results = []
                for result in results:
                    if year and result.year != year:
                        continue
                    if media_type:
                        if result.type != MediaType(media_type):
                            continue
                    if season and result.season != season:
                        continue
                    filtered_results.append(result)

                if filtered_results:
                    result_message = f"找到 {len(filtered_results)} 个相关媒体资源"
                    self.send_tool_message(result_message, title="搜索成功")

                    # 发送详细结果
                    for i, result in enumerate(filtered_results[:5]):  # 只显示前5个结果
                        media_info = f"{i + 1}. {result.title} ({result.year}) - {result.type.value if result.type else '未知'}"
                        self.send_tool_message(media_info, title="搜索结果")

                    return json.dumps([r.to_dict() for r in filtered_results], ensure_ascii=False, indent=2)
                else:
                    error_message = f"未找到符合条件的媒体资源: {title}"
                    self.send_tool_message(error_message, title="搜索完成")
                    return error_message
            else:
                error_message = f"未找到相关媒体资源: {title}"
                self.send_tool_message(error_message, title="搜索完成")
                return error_message
        except Exception as e:
            error_message = f"搜索媒体失败: {str(e)}"
            logger.error(f"搜索媒体失败: {e}", exc_info=True)
            self.send_tool_message(error_message, title="搜索失败")
            return error_message
