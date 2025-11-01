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
                                  description="Filter subscriptions by status: 'R' for enabled subscriptions, 'P' for disabled ones, 'all' for all subscriptions")
    media_type: Optional[str] = Field("all",
                                      description="Filter by media type: 'movie' for films, 'tv' for television series, 'all' for all types")


class QuerySubscribesTool(MoviePilotTool):
    name: str = "query_subscribes"
    description: str = "Query subscription status and list all user subscriptions. Shows active subscriptions, their download status, and configuration details."
    args_schema: Type[BaseModel] = QuerySubscribesInput

    async def run(self, status: Optional[str] = "all", media_type: Optional[str] = "all", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: status={status}, media_type={media_type}")
        try:
            subscribe_oper = SubscribeOper()
            subscribes = subscribe_oper.list()
            filtered_subscribes = []
            for sub in subscribes:
                if status != "all" and sub.state != status:
                    continue
                if media_type != "all" and sub.type != media_type:
                    continue
                filtered_subscribes.append(sub)
            if filtered_subscribes:
                return json.dumps([s.to_dict() for s in filtered_subscribes], ensure_ascii=False, indent=2)
            return "未找到相关订阅。"
        except Exception as e:
            logger.error(f"查询订阅失败: {e}", exc_info=True)
            return f"查询订阅时发生错误: {str(e)}"
