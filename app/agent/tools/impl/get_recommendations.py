"""获取推荐工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.chain.recommend import RecommendChain
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class GetRecommendationsInput(BaseModel):
    """获取推荐工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    source: Optional[str] = Field("tmdb_trending", description="Recommendation source: 'tmdb_trending' for TMDB trending content, 'douban_hot' for Douban popular content, 'bangumi_calendar' for Bangumi anime calendar")
    media_type: Optional[str] = Field("all", description="Type of media content: 'movie' for films, 'tv' for television series, 'all' for all types")
    limit: Optional[int] = Field(20, description="Maximum number of recommendations to return (default: 20, maximum: 100)")


class GetRecommendationsTool(MoviePilotTool):
    name: str = "get_recommendations"
    description: str = "Get trending and popular media recommendations from various sources. Returns curated lists of popular movies, TV shows, and anime based on different criteria like trending, ratings, or calendar schedules."
    args_schema: Type[BaseModel] = GetRecommendationsInput

    async def _arun(self, source: Optional[str] = "tmdb_trending",
                    media_type: Optional[str] = "all", limit: Optional[int] = 20, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: source={source}, media_type={media_type}, limit={limit}")
        try:
            recommend_chain = RecommendChain()
            results = []
            if source == "tmdb_trending":
                results = recommend_chain.tmdb_trending(limit=limit)
            elif source == "douban_hot":
                if media_type == "movie":
                    results = recommend_chain.douban_movie_hot(limit=limit)
                elif media_type == "tv":
                    results = recommend_chain.douban_tv_hot(limit=limit)
                else: # all
                    results.extend(recommend_chain.douban_movie_hot(limit=limit))
                    results.extend(recommend_chain.douban_tv_hot(limit=limit))
            elif source == "bangumi_calendar":
                results = recommend_chain.bangumi_calendar(limit=limit)
            
            if results:
                # 使用 to_dict() 方法
                return json.dumps(results)
            return "未找到推荐内容。"
        except Exception as e:
            logger.error(f"获取推荐失败: {e}", exc_info=True)
            return f"获取推荐时发生错误: {str(e)}"
