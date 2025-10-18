"""获取推荐工具"""

import json
from typing import Optional

from app.chain.recommend import RecommendChain
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class GetRecommendationsTool(MoviePilotTool):
    name: str = "get_recommendations"
    description: str = "获取热门媒体推荐，包括电影、电视剧等热门内容。"

    async def _arun(self, explanation: str, source: Optional[str] = "tmdb_trending", 
                    media_type: Optional[str] = "all", limit: Optional[int] = 20) -> str:
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
                return json.dumps([r.dict() for r in results], ensure_ascii=False, indent=2)
            return "未找到推荐内容。"
        except Exception as e:
            logger.error(f"获取推荐失败: {e}")
            return f"获取推荐时发生错误: {str(e)}"
