"""查询订阅工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db.subscribe_oper import SubscribeOper
from app.log import logger


class QuerySubscribesInput(BaseModel):
    """查询订阅工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    status: Optional[str] = Field("all",
                                  description="Filter subscriptions by status: 'R' for enabled subscriptions, 'S' for paused ones, 'all' for all subscriptions")
    media_type: Optional[str] = Field("all",
                                      description="Filter by media type: '电影' for films, '电视剧' for television series, 'all' for all types")


class QuerySubscribesTool(MoviePilotTool):
    name: str = "query_subscribes"
    description: str = "Query subscription status and list all user subscriptions. Shows active subscriptions, their download status, and configuration details."
    args_schema: Type[BaseModel] = QuerySubscribesInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        status = kwargs.get("status", "all")
        media_type = kwargs.get("media_type", "all")
        
        parts = ["正在查询订阅"]
        
        # 根据状态过滤条件生成提示
        if status != "all":
            status_map = {"R": "已启用", "S": "已暂停"}
            parts.append(f"状态: {status_map.get(status, status)}")
        
        # 根据媒体类型过滤条件生成提示
        if media_type != "all":
            parts.append(f"类型: {media_type}")
        
        return " | ".join(parts) if len(parts) > 1 else parts[0]

    async def run(self, status: Optional[str] = "all", media_type: Optional[str] = "all", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: status={status}, media_type={media_type}")
        try:
            subscribe_oper = SubscribeOper()
            subscribes = await subscribe_oper.async_list()
            filtered_subscribes = []
            for sub in subscribes:
                if status != "all" and sub.state != status:
                    continue
                if media_type != "all" and sub.type != media_type:
                    continue
                filtered_subscribes.append(sub)
            if filtered_subscribes:
                # 限制最多50条结果
                total_count = len(filtered_subscribes)
                limited_subscribes = filtered_subscribes[:50]
                # 精简字段，只保留关键信息
                simplified_subscribes = []
                for s in limited_subscribes:
                    simplified = {
                        "id": s.id,
                        "name": s.name,
                        "year": s.year,
                        "type": s.type,
                        "season": s.season,
                        "tmdbid": s.tmdbid,
                        "doubanid": s.doubanid,
                        "bangumiid": s.bangumiid,
                        "poster": s.poster,
                        "vote": s.vote,
                        "state": s.state,
                        "total_episode": s.total_episode,
                        "lack_episode": s.lack_episode,
                        "last_update": s.last_update,
                        "username": s.username
                    }
                    simplified_subscribes.append(simplified)
                result_json = json.dumps(simplified_subscribes, ensure_ascii=False, indent=2)
                # 如果结果被裁剪，添加提示信息
                if total_count > 50:
                    return f"注意：查询结果共找到 {total_count} 条，为节省上下文空间，仅显示前 50 条结果。\n\n{result_json}"
                return result_json
            return "未找到相关订阅"
        except Exception as e:
            logger.error(f"查询订阅失败: {e}", exc_info=True)
            return f"查询订阅时发生错误: {str(e)}"
