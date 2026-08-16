"""插件声明能力的聚合：命令、接口、服务、模块、动作与智能体工具。"""
from typing import Any, Dict, List, Optional, Callable


from app.foundation.reflection import ObjectUtils
from app.runtime.extensions.plugin_instance import matches_plugin
from app.runtime.log import logger

LegacyDiagnosticsConfigurator = Callable[..., None]
LegacyImportScanner = Callable[..., None]
LegacyPluginImportPreparer = Callable[..., None]
PluginInstallReporter = Callable[..., None]



class _PluginCapabilityMixin:
    """插件声明能力的聚合：命令、接口、服务、模块、动作与智能体工具。"""

    def clear_plugin_agent_tools_cache(self) -> None:
        """
        清空插件智能体工具注册表缓存。
        """
        with self._plugin_agent_tools_cache_lock:
            self._plugin_agent_tools_cache.clear()
            self._plugin_agent_tools_revision += 1

    def get_plugin_agent_tools_revision(self) -> int:
        """
        获取插件智能体工具注册表版本号。
        """
        with self._plugin_agent_tools_cache_lock:
            return self._plugin_agent_tools_revision

    def get_plugin_commands(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件命令
        [{
            "cmd": "/xx",
            "event": EventType.xx,
            "desc": "xxxx",
            "data": {},
            "pid": "",
        }]
        """
        ret_commands = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if pid and not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_command") and ObjectUtils.check_method(plugin.get_command):
                try:
                    if not plugin.get_state():
                        continue
                    commands = plugin.get_command() or []
                    for command in commands:
                        command["pid"] = plugin_id
                    ret_commands.extend(commands)
                except Exception as e:
                    logger.error(f"获取插件命令出错：{str(e)}")
        return ret_commands

    def get_plugin_apis(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件API
        [{
            "path": "/xx",
            "endpoint": self.xxx,
            "methods": ["GET", "POST"],
            "summary": "API名称",
            "description": "API说明",
            "allow_anonymous": false
        }]
        """
        ret_apis = []
        if pid:
            plugins = {key: plugin
                       for key, plugin in self._running_plugins.items()
                       if matches_plugin(key, pid)}
        else:
            plugins = self._running_plugins
        for plugin_id, plugin in plugins.items():
            if pid and not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_api") and ObjectUtils.check_method(plugin.get_api):
                try:
                    apis = plugin.get_api() or []
                    for api in apis:
                        api["path"] = f"/{plugin_id}{api['path']}"
                        if not api.get("auth"):
                            api["auth"] = "apikey"
                    ret_apis.extend(apis)
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} API出错：{str(e)}")
        return ret_apis

    def get_plugin_services(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件服务
        [{
            "id": "服务ID",
            "name": "服务名称",
            "trigger": "触发器：cron、interval、date、CronTrigger.from_crontab()",
            "func": self.xxx,
            "kwargs": {} # 定时器参数,
            "func_kwargs": {} # 方法参数
        }]
        """
        ret_services = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if pid and not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_service") and ObjectUtils.check_method(plugin.get_service):
                try:
                    if not plugin.get_state():
                        continue
                    services = plugin.get_service() or []
                    # 带出归属实例键：同一插件的多个实例声明同名服务，调度器据此区分
                    for service in services:
                        if not service:
                            continue
                        ret_services.append({**service, "pid": plugin_id})
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 服务出错：{str(e)}")
        return ret_services

    def get_plugin_modules(self, pid: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
        """
        获取插件模块
        {
            plugin_id: {
                method: function
            }
        }
        """
        ret_modules = {}
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if pid and not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_module") and ObjectUtils.check_method(plugin.get_module):
                try:
                    if not plugin.get_state():
                        continue
                    plugin_module = plugin.get_module() or []
                    ret_modules[(plugin_id, plugin.get_name())] = plugin_module
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 模块出错：{str(e)}")
        return ret_modules

    def get_plugin_actions(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件动作
        [{
            "id": "动作ID",
            "name": "动作名称",
            "func": self.xxx,
            "kwargs": {} # 需要附加传递的参数
        }]
        """
        ret_actions = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(self._running_plugins)
        for plugin_id, plugin in running_plugins_snapshot.items():
            if pid and not matches_plugin(plugin_id, pid):
                continue
            if hasattr(plugin, "get_actions") and ObjectUtils.check_method(plugin.get_actions):
                try:
                    if not plugin.get_state():
                        continue
                    actions = plugin.get_actions()
                    if actions:
                        ret_actions.append({
                            "plugin_id": plugin_id,
                            "plugin_name": plugin.plugin_name,
                            "actions": actions
                        })
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 动作出错：{str(e)}")
        return ret_actions

    @staticmethod
    def _copy_plugin_agent_tools(
        tools_info: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        复制插件智能体工具注册信息，避免调用方修改缓存内容。
        """
        return [
            {
                **plugin_info,
                "tools": list(plugin_info.get("tools", [])),
            }
            for plugin_info in tools_info
        ]

    def get_plugin_agent_tools(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        获取插件智能体工具
        [{
            "plugin_id": "插件ID",
            "plugin_name": "插件名称",
            "tools": [ToolClass1, ToolClass2, ...]
        }]
        """
        cache_key = pid or "__all__"
        for _attempt in range(self.AGENT_TOOLS_BUILD_MAX_ATTEMPTS):
            with self._plugin_agent_tools_cache_lock:
                cache_revision = self._plugin_agent_tools_revision
                cached_tools = self._plugin_agent_tools_cache.get(cache_key)
            if cached_tools is not None:
                return self._copy_plugin_agent_tools(cached_tools)

            ret_tools = []
            # 创建字典快照避免并发修改
            running_plugins_snapshot = dict(self._running_plugins)
            for plugin_id, plugin in running_plugins_snapshot.items():
                if pid and not matches_plugin(plugin_id, pid):
                    continue
                if hasattr(plugin, "get_agent_tools") and ObjectUtils.check_method(
                    plugin.get_agent_tools
                ):
                    try:
                        if not plugin.get_state():
                            continue
                        tools = plugin.get_agent_tools()
                        if tools:
                            ret_tools.append({
                                "plugin_id": plugin_id,
                                "plugin_name": plugin.plugin_name,
                                "tools": tools
                            })
                    except Exception as e:
                        logger.error(f"获取插件 {plugin_id} 智能体工具出错：{str(e)}")
            with self._plugin_agent_tools_cache_lock:
                if cache_revision != self._plugin_agent_tools_revision:
                    # 插件状态在注册表构建期间发生变化，重新读取以避免写回过期快照。
                    continue
                self._plugin_agent_tools_cache[cache_key] = self._copy_plugin_agent_tools(
                    ret_tools
                )
                return ret_tools
        raise RuntimeError("插件工具注册表持续变化，无法建立当前快照")
