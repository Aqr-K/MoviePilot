"""获取推荐工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.recommend import RecommendChain
from app.log import logger


class GetRecommendationsInput(BaseModel):
    """获取推荐工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    source: Optional[str] = Field("tmdb_trending",
                                  description="Recommendation source: 'tmdb_trending' for TMDB trending content, 'douban_hot' for Douban popular content, 'bangumi_calendar' for Bangumi anime calendar")
    media_type: Optional[str] = Field("all",
                                      description="Type of media content: '电影' for films, '电视剧' for television series or anime series, 'all' for all types")
    limit: Optional[int] = Field(20,
                                 description="Maximum number of recommendations to return (default: 20, maximum: 100)")


class GetRecommendationsTool(MoviePilotTool):
    name: str = "get_recommendations"
    description: str = "Get trending and popular media recommendations from various sources. Returns curated lists of popular movies, TV shows, and anime based on different criteria like trending, ratings, or calendar schedules."
    args_schema: Type[BaseModel] = GetRecommendationsInput

    async def run(self, source: Optional[str] = "tmdb_trending",
                  media_type: Optional[str] = "all", limit: Optional[int] = 20, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: source={source}, media_type={media_type}, limit={limit}")
        try:
            name_dicts = {
                "tmdb_trending": "TMDB 热门推荐",
                "douban_hot": "豆瓣热门推荐",
                "bangumi_calendar": "番组计划推荐"
            }
            recommend_chain = RecommendChain()
            results = []
            if source == "tmdb_trending":
                results = await recommend_chain.async_tmdb_trending(limit=limit)
            elif source == "douban_hot":
                if media_type == "movie":
                    results = await recommend_chain.async_douban_movie_hot(limit=limit)
                elif media_type == "tv":
                    results = await recommend_chain.async_douban_tv_hot(limit=limit)
                else:  # all
                    results.extend(await recommend_chain.async_douban_movie_hot(limit=limit))
                    results.extend(await recommend_chain.async_douban_tv_hot(limit=limit))
            elif source == "bangumi_calendar":
                results = await recommend_chain.async_bangumi_calendar(limit=limit)

            if results:
                # 限制最多20条结果
                total_count = len(results)
                limited_results = results[:20]
                # 精简字段，只保留关键信息
                simplified_results = []
                for r in limited_results:
                    # r 已经是字典格式（to_dict的结果）
                    simplified = {
                        "title": r.get("title"),
                        "en_title": r.get("en_title"),
                        "year": r.get("year"),
                        "type": r.get("type"),
                        "season": r.get("season"),
                        "tmdb_id": r.get("tmdb_id"),
                        "imdb_id": r.get("imdb_id"),
                        "douban_id": r.get("douban_id"),
                        "overview": r.get("overview", "")[:200] + "..." if r.get("overview") and len(r.get("overview", "")) > 200 else r.get("overview"),
                        "vote_average": r.get("vote_average"),
                        "poster_path": r.get("poster_path"),
                        "detail_link": r.get("detail_link")
                    }
                    simplified_results.append(simplified)
                result_json = json.dumps(simplified_results, ensure_ascii=False, indent=2)
                # 如果结果被裁剪，添加提示信息
                if total_count > 20:
                    return f"注意：推荐结果共找到 {total_count} 条，为节省上下文空间，仅显示前 20 条结果。\n\n{result_json}"
                return result_json
            return "未找到推荐内容。"
        except Exception as e:
            logger.error(f"获取推荐失败: {e}", exc_info=True)
            return f"获取推荐时发生错误: {str(e)}"
