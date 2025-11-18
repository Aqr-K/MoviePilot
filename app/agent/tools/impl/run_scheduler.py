"""运行定时服务工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.log import logger
from app.scheduler import Scheduler


class RunSchedulerInput(BaseModel):
    """运行定时服务工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    job_id: str = Field(..., description="The ID of the scheduled job to run (can be obtained from query_schedulers tool)")


class RunSchedulerTool(MoviePilotTool):
    name: str = "run_scheduler"
    description: str = "Manually trigger a scheduled task to run immediately. This will execute the specified scheduler job by its ID."
    args_schema: Type[BaseModel] = RunSchedulerInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据运行参数生成友好的提示消息"""
        job_id = kwargs.get("job_id", "")
        return f"正在运行定时服务 (ID: {job_id})"

    async def run(self, job_id: str, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: job_id={job_id}")

        try:
            scheduler = Scheduler()
            # 检查定时服务是否存在
            schedulers = scheduler.list()
            job_exists = False
            job_name = None
            for s in schedulers:
                if s.id == job_id:
                    job_exists = True
                    job_name = s.name
                    break
            
            if not job_exists:
                return f"定时服务 ID {job_id} 不存在，请使用 query_schedulers 工具查询可用的定时服务"
            
            # 运行定时服务
            scheduler.start(job_id)
            
            return f"成功触发定时服务：{job_name} (ID: {job_id})"
        except Exception as e:
            logger.error(f"运行定时服务失败: {e}", exc_info=True)
            return f"运行定时服务时发生错误: {str(e)}"

