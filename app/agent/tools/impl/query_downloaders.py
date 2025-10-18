"""查询下载器工具"""

import json

from app.db.systemconfig_oper import SystemConfigOper
from app.log import logger
from app.schemas.types import SystemConfigKey
from app.agent.tools.base import MoviePilotTool


class QueryDownloadersTool(MoviePilotTool):
    name: str = "query_downloaders"
    description: str = "查询下载器配置，查看可用的下载器列表和配置信息。"

    async def _arun(self, explanation: str) -> str:
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
