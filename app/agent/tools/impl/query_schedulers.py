"""查询定时服务工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger
from app.scheduler import Scheduler


class QuerySchedulersInput(BaseModel):
    """查询定时服务工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")


class QuerySchedulersTool(MoviePilotTool):
    name: str = "query_schedulers"
    description: str = "Query scheduled tasks and list all available scheduler jobs. Shows job status, next run time, and provider information."
    args_schema: Type[BaseModel] = QuerySchedulersInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """生成友好的提示消息"""
        return "正在查询定时服务"

    async def run(self, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}")
        try:
            scheduler = Scheduler()
            schedulers = scheduler.list()
            if schedulers:
                # 转换为字典列表以便JSON序列化
                schedulers_list = []
                for s in schedulers:
                    schedulers_list.append({
                        "id": s.id,
                        "name": s.name,
                        "provider": s.provider,
                        "status": s.status,
                        "next_run": s.next_run
                    })
                result_json = json.dumps(schedulers_list, ensure_ascii=False, indent=2)
                # 限制最多30条结果
                total_count = len(schedulers_list)
                if total_count > 30:
                    limited_schedulers = schedulers_list[:30]
                    limited_json = json.dumps(limited_schedulers, ensure_ascii=False, indent=2)
                    return f"注意：查询结果共找到 {total_count} 条，为节省上下文空间，仅显示前 30 条结果。\n\n{limited_json}"
                return result_json
            return "未找到定时服务"
        except Exception as e:
            logger.error(f"查询定时服务失败: {e}", exc_info=True)
            return f"查询定时服务时发生错误: {str(e)}"

