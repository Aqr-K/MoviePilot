"""查询已安装插件工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.plugin import PluginManager
from app.log import logger


class QueryInstalledPluginsInput(BaseModel):
    """查询已安装插件工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )


class QueryInstalledPluginsTool(MoviePilotTool):
    name: str = "query_installed_plugins"
    description: str = (
        "Query all installed plugins in MoviePilot. Returns a list of installed plugins with their ID, name, "
        "description, version, author, running state, and other information. "
        "Use this tool to discover what plugins are available before querying plugin capabilities or running plugin commands."
    )
    require_admin: bool = True
    args_schema: Type[BaseModel] = QueryInstalledPluginsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """生成友好的提示消息"""
        return "查询已安装插件"

    @staticmethod
    def _list_installed_plugins() -> list[dict]:
        """读取已加载插件的内存快照。"""
        plugin_manager = PluginManager()
        local_plugins = plugin_manager.get_local_plugins()
        installed_plugins = [plugin for plugin in local_plugins if plugin.installed]
        return [
            {
                "id": plugin.id,
                "plugin_name": plugin.plugin_name,
                "plugin_desc": plugin.plugin_desc,
                "plugin_version": plugin.plugin_version,
                "plugin_author": plugin.plugin_author,
                "state": plugin.state,
                "has_page": plugin.has_page,
            }
            for plugin in installed_plugins
        ]

    async def run(self, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}")
        try:
            installed_plugins = self._list_installed_plugins()
            if not installed_plugins:
                return "当前没有已安装的插件"
            result_json = json.dumps(installed_plugins, ensure_ascii=False, indent=2)
            return result_json
        except Exception as e:
            logger.error(f"查询已安装插件失败: {e}", exc_info=True)
            return f"查询已安装插件时发生错误: {str(e)}"
