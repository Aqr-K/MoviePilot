"""执行工作流工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.workflow import WorkflowChain
from app.db import AsyncSessionFactory
from app.db.workflow_oper import WorkflowOper
from app.log import logger


class RunWorkflowInput(BaseModel):
    """执行工作流工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    workflow_identifier: str = Field(..., description="Workflow identifier: can be workflow ID (integer as string) or workflow name")
    from_begin: Optional[bool] = Field(True, description="Whether to run workflow from the beginning (default: True, if False will continue from last executed action)")


class RunWorkflowTool(MoviePilotTool):
    name: str = "run_workflow"
    description: str = "Execute a specific workflow manually. Can run workflow by ID or name. Supports running from the beginning or continuing from the last executed action."
    args_schema: Type[BaseModel] = RunWorkflowInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据工作流参数生成友好的提示消息"""
        workflow_identifier = kwargs.get("workflow_identifier", "")
        from_begin = kwargs.get("from_begin", True)
        
        message = f"正在执行工作流: {workflow_identifier}"
        if not from_begin:
            message += " (从上次位置继续)"
        else:
            message += " (从头开始)"
        
        return message

    async def run(self, workflow_identifier: str,
                  from_begin: Optional[bool] = True, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: workflow_identifier={workflow_identifier}, from_begin={from_begin}")

        try:
            # 获取数据库会话
            async with AsyncSessionFactory() as db:
                workflow_oper = WorkflowOper(db)
                
                # 尝试解析为工作流ID
                workflow = None
                if workflow_identifier.isdigit():
                    # 如果是数字，尝试作为工作流ID查询
                    workflow = await workflow_oper.async_get(int(workflow_identifier))
                
                # 如果不是ID或ID查询失败，尝试按名称查询
                if not workflow:
                    workflow = await workflow_oper.async_get_by_name(workflow_identifier)
                
                if not workflow:
                    return f"未找到工作流：{workflow_identifier}，请使用 query_workflows 工具查询可用的工作流"
                
                # 执行工作流
                workflow_chain = WorkflowChain()
                state, errmsg = workflow_chain.process(workflow.id, from_begin=from_begin)
                
                if not state:
                    return f"执行工作流失败：{workflow.name} (ID: {workflow.id})\n错误原因：{errmsg}"
                else:
                    return f"工作流执行成功：{workflow.name} (ID: {workflow.id})"
        except Exception as e:
            logger.error(f"执行工作流失败: {e}", exc_info=True)
            return f"执行工作流时发生错误: {str(e)}"

