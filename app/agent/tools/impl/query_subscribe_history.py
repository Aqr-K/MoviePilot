"""查询订阅历史工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db import AsyncSessionFactory
from app.db.models.subscribehistory import SubscribeHistory
from app.log import logger


class QuerySubscribeHistoryInput(BaseModel):
    """查询订阅历史工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    media_type: Optional[str] = Field("all", description="Filter by media type: '电影' for films, '电视剧' for television series, 'all' for all types (default: 'all')")
    name: Optional[str] = Field(None, description="Filter by media name (partial match, optional)")


class QuerySubscribeHistoryTool(MoviePilotTool):
    name: str = "query_subscribe_history"
    description: str = "Query subscription history records. Shows completed subscriptions with their details including name, type, rating, completion date, and other subscription information. Supports filtering by media type and name. Returns up to 30 records."
    args_schema: Type[BaseModel] = QuerySubscribeHistoryInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        media_type = kwargs.get("media_type", "all")
        name = kwargs.get("name")
        
        parts = ["正在查询订阅历史"]
        
        if media_type != "all":
            parts.append(f"类型: {media_type}")
        if name:
            parts.append(f"名称: {name}")
        
        return " | ".join(parts) if len(parts) > 1 else parts[0]

    async def run(self, media_type: Optional[str] = "all",
                  name: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: media_type={media_type}, name={name}")

        try:
            # 获取数据库会话
            async with AsyncSessionFactory() as db:
                # 根据类型查询
                if media_type == "all":
                    # 查询所有类型，需要分别查询电影和电视剧
                    movie_history = await SubscribeHistory.async_list_by_type(db, mtype="movie", page=1, count=100)
                    tv_history = await SubscribeHistory.async_list_by_type(db, mtype="tv", page=1, count=100)
                    all_history = list(movie_history) + list(tv_history)
                    # 按日期排序
                    all_history.sort(key=lambda x: x.date or "", reverse=True)
                else:
                    # 查询指定类型
                    all_history = await SubscribeHistory.async_list_by_type(db, mtype=media_type, page=1, count=100)
                
                # 按名称过滤
                filtered_history = []
                if name:
                    name_lower = name.lower()
                    for record in all_history:
                        if record.name and name_lower in record.name.lower():
                            filtered_history.append(record)
                else:
                    filtered_history = all_history
                
                if not filtered_history:
                    return "未找到相关订阅历史记录"
                
                # 限制最多30条
                total_count = len(filtered_history)
                limited_history = filtered_history[:30]
                
                # 转换为字典格式，只保留关键信息
                simplified_records = []
                for record in limited_history:
                    simplified = {
                        "id": record.id,
                        "name": record.name,
                        "year": record.year,
                        "type": record.type,
                        "season": record.season,
                        "tmdbid": record.tmdbid,
                        "doubanid": record.doubanid,
                        "bangumiid": record.bangumiid,
                        "poster": record.poster,
                        "vote": record.vote,
                        "total_episode": record.total_episode,
                        "date": record.date,
                        "username": record.username
                    }
                    # 添加过滤规则信息（如果有）
                    if record.filter:
                        simplified["filter"] = record.filter
                    if record.quality:
                        simplified["quality"] = record.quality
                    if record.resolution:
                        simplified["resolution"] = record.resolution
                    simplified_records.append(simplified)
                
                result_json = json.dumps(simplified_records, ensure_ascii=False, indent=2)
                
                # 如果结果被裁剪，添加提示信息
                if total_count > 30:
                    return f"注意：查询结果共找到 {total_count} 条，为节省上下文空间，仅显示前 30 条结果。\n\n{result_json}"
                
                return result_json
        except Exception as e:
            logger.error(f"查询订阅历史失败: {e}", exc_info=True)
            return f"查询订阅历史时发生错误: {str(e)}"

