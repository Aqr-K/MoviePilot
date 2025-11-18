"""查询下载器工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db.systemconfig_oper import SystemConfigOper
from app.log import logger
from app.schemas.types import SystemConfigKey


class QueryDownloadersInput(BaseModel):
    """查询下载器工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")


class QueryDownloadersTool(MoviePilotTool):
    name: str = "query_downloaders"
    description: str = "Query downloader configuration and list all available downloaders. Shows downloader status, connection details, and configuration settings."
    args_schema: Type[BaseModel] = QueryDownloadersInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """生成友好的提示消息"""
        return "正在查询下载器配置"

    async def run(self, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}")
        try:
            system_config_oper = SystemConfigOper()
            downloaders_config = system_config_oper.get(SystemConfigKey.Downloaders)
            if downloaders_config:
                return json.dumps(downloaders_config, ensure_ascii=False, indent=2)
            return "未配置下载器。"
        except Exception as e:
            logger.error(f"查询下载器失败: {e}")
            return f"查询下载器时发生错误: {str(e)}"
