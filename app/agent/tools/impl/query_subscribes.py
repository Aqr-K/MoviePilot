"""查询订阅工具"""

import json
from typing import Optional

from app.db.subscribe_oper import SubscribeOper
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class QuerySubscribesTool(MoviePilotTool):
    name: str = "query_subscribes"
    description: str = "查询订阅状态，查看用户的订阅列表和状态。"

    async def _arun(self, explanation: str, status: Optional[str] = "all", 
                    media_type: Optional[str] = "all") -> str:
        logger.info(f"执行工具: {self.name}, 参数: status={status}, media_type={media_type}")
        try:
            subscribe_oper = SubscribeOper()
            subscribes = subscribe_oper.list()
            filtered_subscribes = []
            for sub in subscribes:
                if status != "all" and sub.status != status:
                    continue
                if media_type != "all" and sub.type != media_type:
                    continue
                filtered_subscribes.append(sub)
            if filtered_subscribes:
                return json.dumps([s.dict() for s in filtered_subscribes], ensure_ascii=False, indent=2)
            return "未找到相关订阅。"
        except Exception as e:
            logger.error(f"查询订阅失败: {e}")
            return f"查询订阅时发生错误: {str(e)}"
