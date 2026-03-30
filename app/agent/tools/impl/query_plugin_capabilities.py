"""查询插件能力工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.plugin import PluginManager
from app.log import logger


class QueryPluginCapabilitiesInput(BaseModel):
    """查询插件能力工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )
    plugin_id: Optional[str] = Field(
        None,
        description="Optional plugin ID to query capabilities for a specific plugin. "
        "If not provided, returns capabilities of all running plugins. "
        "Use query_installed_plugins tool to get the plugin IDs first.",
    )


class QueryPluginCapabilitiesTool(MoviePilotTool):
    name: str = "query_plugin_capabilities"
    description: str = (
        "Query the capabilities of installed plugins, including supported commands and scheduled services. "
        "Commands are slash-commands (e.g. /xxx) that can be executed via the run_plugin_command tool. "
        "Scheduled services are periodic tasks that can be triggered via the run_scheduler tool. "
        "Optionally specify a plugin_id to query a specific plugin, or omit to query all running plugins."
    )
    require_admin: bool = True
    args_schema: Type[BaseModel] = QueryPluginCapabilitiesInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """生成友好的提示消息"""
        plugin_id = kwargs.get("plugin_id")
        if plugin_id:
            return f"正在查询插件 {plugin_id} 的能力"
        return "正在查询所有插件的能力"

    async def run(self, plugin_id: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: plugin_id={plugin_id}")
        try:
            plugin_manager = PluginManager()
            result = {}

            # 获取插件命令
            commands = plugin_manager.get_plugin_commands(pid=plugin_id)
            if commands:
                commands_list = []
                for cmd in commands:
                    cmd_info = {
                        "cmd": cmd.get("cmd"),
                        "desc": cmd.get("desc"),
                        "plugin_id": cmd.get("pid"),
                    }
                    # data 字段可能包含额外参数信息
                    if cmd.get("data"):
                        cmd_info["data"] = cmd.get("data")
                    commands_list.append(cmd_info)
                result["commands"] = commands_list

            # 获取插件动作
            actions = plugin_manager.get_plugin_actions(pid=plugin_id)
            if actions:
                actions_list = []
                for action_group in actions:
                    plugin_actions = {
                        "plugin_id": action_group.get("plugin_id"),
                        "plugin_name": action_group.get("plugin_name"),
                        "actions": [],
                    }
                    for action in action_group.get("actions", []):
                        plugin_actions["actions"].append(
                            {
                                "id": action.get("id"),
                                "name": action.get("name"),
                            }
                        )
                    actions_list.append(plugin_actions)
                result["actions"] = actions_list

            # 获取插件定时服务
            services = plugin_manager.get_plugin_services(pid=plugin_id)
            if services:
                services_list = []
                for svc in services:
                    svc_info = {
                        "id": svc.get("id"),
                        "name": svc.get("name"),
                    }
                    # 包含触发器信息
                    trigger = svc.get("trigger")
                    if trigger:
                        svc_info["trigger"] = str(trigger)
                    # 包含定时器参数
                    svc_kwargs = svc.get("kwargs")
                    if svc_kwargs:
                        svc_info["trigger_kwargs"] = {
                            k: str(v) for k, v in svc_kwargs.items()
                        }
                    services_list.append(svc_info)
                result["services"] = services_list

            if not result:
                if plugin_id:
                    return f"插件 {plugin_id} 没有注册任何命令、动作或定时服务"
                return "当前没有运行中的插件注册了命令、动作或定时服务"

            return json.dumps(result, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"查询插件能力失败: {e}", exc_info=True)
            return f"查询插件能力时发生错误: {str(e)}"
