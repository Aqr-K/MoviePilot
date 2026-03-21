"""查询订阅工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db.subscribe_oper import SubscribeOper
from app.log import logger
from app.schemas.subscribe import Subscribe as SubscribeSchema
from app.schemas.types import MediaType

QUERY_SUBSCRIBE_OUTPUT_FIELDS = [
    "id",
    "name",
    "year",
    "type",
    "season",
    "total_episode",
    "start_episode",
    "lack_episode",
    "filter",
    "include",
    "exclude",
    "quality",
    "resolution",
    "effect",
    "state",
    "last_update",
    "sites",
    "downloader",
    "best_version",
    "save_path",
    "custom_words",
    "media_category",
    "filter_groups",
    "episode_group"
]


class QuerySubscribesInput(BaseModel):
    """查询订阅工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    status: Optional[str] = Field("all",
                                  description="Filter subscriptions by status: 'R' for enabled subscriptions, 'S' for paused ones, 'all' for all subscriptions")
    media_type: Optional[str] = Field("all",
                                      description="Allowed values: movie, tv, all")
    tmdb_id: Optional[int] = Field(None, description="Filter by TMDB ID to check if a specific media is already subscribed")
    douban_id: Optional[str] = Field(None, description="Filter by Douban ID to check if a specific media is already subscribed")


class QuerySubscribesTool(MoviePilotTool):
    name: str = "query_subscribes"
    description: str = "Query subscription status and list user subscriptions. Returns full subscription parameters for each matched subscription."
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

    async def run(self, status: Optional[str] = "all", media_type: Optional[str] = "all",
                  tmdb_id: Optional[int] = None, douban_id: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: status={status}, media_type={media_type}, tmdb_id={tmdb_id}, douban_id={douban_id}")
        try:
            if media_type != "all" and not MediaType.from_agent(media_type):
                return f"错误：无效的媒体类型 '{media_type}'，支持的类型：'movie', 'tv', 'all'"

            subscribe_oper = SubscribeOper()
            subscribes = await subscribe_oper.async_list()
            filtered_subscribes = []
            for sub in subscribes:
                if status != "all" and sub.state != status:
                    continue
                if media_type != "all" and sub.type != MediaType.from_agent(media_type).value:
                    continue
                if tmdb_id is not None and sub.tmdbid != tmdb_id:
                    continue
                if douban_id is not None and sub.doubanid != douban_id:
                    continue
                filtered_subscribes.append(sub)
            if filtered_subscribes:
                # 限制最多50条结果
                total_count = len(filtered_subscribes)
                limited_subscribes = filtered_subscribes[:50]
                full_subscribes = [
                    SubscribeSchema.model_validate(s, from_attributes=True).model_dump(
                        include=set(QUERY_SUBSCRIBE_OUTPUT_FIELDS),
                        exclude_none=True
                    )
                    for s in limited_subscribes
                ]
                result_json = json.dumps(full_subscribes, ensure_ascii=False, indent=2)
                # 如果结果被裁剪，添加提示信息
                if total_count > 50:
                    return f"注意：查询结果共找到 {total_count} 条，为节省上下文空间，仅显示前 50 条结果。\n\n{result_json}"
                return result_json
            return "未找到相关订阅"
        except Exception as e:
            logger.error(f"查询订阅失败: {e}", exc_info=True)
            return f"查询订阅时发生错误: {str(e)}"
