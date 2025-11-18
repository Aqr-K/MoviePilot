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

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据推荐参数生成友好的提示消息"""
        source = kwargs.get("source", "tmdb_trending")
        media_type = kwargs.get("media_type", "all")
        limit = kwargs.get("limit", 20)
        
        source_map = {
            "tmdb_trending": "TMDB热门",
            "douban_hot": "豆瓣热门",
            "bangumi_calendar": "番组计划"
        }
        source_desc = source_map.get(source, source)
        
        message = f"正在获取推荐: {source_desc}"
        if media_type != "all":
            message += f" [{media_type}]"
        message += f" (限制: {limit}条)"
        
        return message

    async def run(self, source: Optional[str] = "tmdb_trending",
                  media_type: Optional[str] = "all", limit: Optional[int] = 20, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: source={source}, media_type={media_type}, limit={limit}")
        try:
            recommend_chain = RecommendChain()
            results = []
            if source == "tmdb_trending":
                # async_tmdb_trending 只接受 page 参数，返回固定数量的结果
                # 如果需要限制数量，需要在返回后截取
                results = await recommend_chain.async_tmdb_trending(page=1)
                if limit and limit > 0:
                    results = results[:limit]
            elif source == "douban_hot":
                # async_douban_movie_hot 和 async_douban_tv_hot 接受 page 和 count 参数
                if media_type == "movie":
                    results = await recommend_chain.async_douban_movie_hot(page=1, count=limit)
                elif media_type == "tv":
                    results = await recommend_chain.async_douban_tv_hot(page=1, count=limit)
                else:  # all
                    results.extend(await recommend_chain.async_douban_movie_hot(page=1, count=limit))
                    results.extend(await recommend_chain.async_douban_tv_hot(page=1, count=limit))
            elif source == "bangumi_calendar":
                # async_bangumi_calendar 接受 page 和 count 参数
                results = await recommend_chain.async_bangumi_calendar(page=1, count=limit)

            if results:
                # 限制最多20条结果
                total_count = len(results)
                limited_results = results[:20]
                # 精简字段，只保留关键信息
                simplified_results = []
                for r in limited_results:
                    # r 应该是字典格式（to_dict的结果），但为了安全起见进行检查
                    if not isinstance(r, dict):
                        logger.warning(f"推荐结果格式异常，跳过: {type(r)}")
                        continue
                    
                    # 处理 overview 字段，截断过长的描述
                    overview = r.get("overview") or ""
                    if overview and len(overview) > 200:
                        overview = overview[:200] + "..."
                    
                    simplified = {
                        "title": r.get("title"),
                        "en_title": r.get("en_title"),
                        "year": r.get("year"),
                        "type": r.get("type"),
                        "season": r.get("season"),
                        "tmdb_id": r.get("tmdb_id"),
                        "imdb_id": r.get("imdb_id"),
                        "douban_id": r.get("douban_id"),
                        "overview": overview,
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
