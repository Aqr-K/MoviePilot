"""插件元数据只读聚合访问器。

只读地遍历运行态插件字典（running_plugins）、调用各插件实例的 get_xxx 钩子方法并聚合结果，
对 PluginManager 实例状态的唯一耦合是 running_plugins 这一个字典。均为模块级函数（首参 running_plugins）；
PluginManager 保留委托门面，使 api/agent/command/scheduler/chain 等调用方 PluginManager().get_plugin_xxx()
调用方式不变。
"""
import inspect
import posixpath
import warnings
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException
from starlette import status

from app import schemas
from app.log import logger
from app.utils.object import ObjectUtils


def get_plugin_commands(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
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
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
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

def get_plugin_apis(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
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
        plugins = {pid: running_plugins.get(pid)}
    else:
        plugins = running_plugins
    for plugin_id, plugin in plugins.items():
        if pid and pid != plugin_id:
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

def get_plugin_services(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
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
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
            continue
        if hasattr(plugin, "get_service") and ObjectUtils.check_method(plugin.get_service):
            try:
                if not plugin.get_state():
                    continue
                services = plugin.get_service() or []
                ret_services.extend(services)
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} 服务出错：{str(e)}")
    return ret_services

def get_plugin_modules(running_plugins, pid: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
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
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
            continue
        if hasattr(plugin, "get_module") and ObjectUtils.check_method(plugin.get_module):
            try:
                if not plugin.get_state():
                    continue
                plugin_module = plugin.get_module() or []
                if plugin_module and not getattr(plugin, "_get_module_deprecation_warned", False):
                    setattr(plugin, "_get_module_deprecation_warned", True)
                    _dep_msg = (f"插件 {plugin_id} 使用 get_module() 方法胁持（无契约校验，已废弃），"
                                f"请改用 provides_modules() 走验证注册。")
                    logger.warning(f"[DEPRECATED] {_dep_msg}")
                    try:
                        warnings.warn(_dep_msg, DeprecationWarning, stacklevel=2)
                    except Exception:
                        pass  # 告警升格(-W error)不得影响模块聚合
                ret_modules[(plugin_id, plugin.get_name())] = plugin_module
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} 模块出错：{str(e)}")
    return ret_modules

def _get_plugin_provided(running_plugins, hook_name: str, err_label: str,
                         pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """
    聚合插件经某 provides_* 钩子声明【新增】的对象（模块类或数据对象），按 plugin_id(owner) 归集。
    各 get_plugin_provided_* 的共用实现：快照运行态插件、按 pid 过滤、仅取已启用(get_state)插件、
    调用钩子收集非空结果。hook_name 为钩子方法名，err_label 用于异常日志。
    {
        plugin_id: [item, ...]
    }
    """
    ret: Dict[str, List[Any]] = {}
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
            continue
        hook = getattr(plugin, hook_name, None)
        if hook is not None and ObjectUtils.check_method(hook):
            try:
                if not plugin.get_state():
                    continue
                items = hook() or []
                if items:
                    ret[plugin_id] = list(items)
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} {err_label}出错：{str(e)}")
    return ret

def get_plugin_provided_modules(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_modules() 声明【新增】的系统模块类，按 plugin_id 归集（供 ModuleManager 注册/卸载）。"""
    return _get_plugin_provided(running_plugins, "provides_modules", "注册模块", pid)

def get_plugin_provided_data_sources(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_data_sources() 声明【新增】的数据源（MediaRecognize 域）类，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_data_sources", "注册数据源", pid)

def get_plugin_provided_downloaders(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_downloaders() 声明【新增】的下载器（Downloader 域）类，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_downloaders", "注册下载器", pid)

def get_plugin_provided_notifications(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_notifications() 声明【新增】的消息渠道（Notification 域）类，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_notifications", "注册消息渠道", pid)

def get_plugin_provided_mediaservers(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_mediaservers() 声明【新增】的媒体服务器（MediaServer 域）类，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_mediaservers", "注册媒体服务器", pid)

def get_plugin_provided_discover_sources(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_discover_sources() 声明【新增】的探索数据源（DiscoverMediaSource），按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_discover_sources", "注册探索数据源", pid)

def get_plugin_provided_recommend_sources(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_recommend_sources() 声明【新增】的推荐数据源（RecommendMediaSource），按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_recommend_sources", "注册推荐数据源", pid)

def get_plugin_provided_storages(running_plugins, pid: Optional[str] = None) -> Dict[str, List[type]]:
    """聚合插件经 provides_storages() 声明【新增】的存储器类，按 plugin_id 归集（供 FileManager 注册/卸载）。"""
    return _get_plugin_provided(running_plugins, "provides_storages", "注册存储器", pid)

def get_plugin_provided_auth_providers(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_auth_providers() 声明【新增】的 SSO 登录提供方实例，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_auth_providers", "注册登录提供方", pid)

def get_plugin_provided_channel_capabilities(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_channel_capabilities() 声明【新增】的消息渠道能力矩阵，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_channel_capabilities", "注册渠道能力", pid)

def get_plugin_provided_credential_providers(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_credential_providers() 声明【新增】的主认证 provider 实例，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_credential_providers", "注册主认证提供方", pid)

def get_plugin_provided_mfa_factors(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_mfa_factors() 声明【新增】的 MFA 第二因子实例，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_mfa_factors", "注册MFA因子", pid)

def get_plugin_provided_auth_flows(running_plugins, pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """聚合插件经 provides_auth_flows() 声明【新增】的自定义流程规格实例，按 plugin_id 归集。"""
    return _get_plugin_provided(running_plugins, "provides_auth_flows", "注册认证流程", pid)

def get_plugin_actions(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
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
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
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

def get_plugin_agent_tools(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    获取插件智能体工具
    [{
        "plugin_id": "插件ID",
        "plugin_name": "插件名称",
        "tools": [ToolClass1, ToolClass2, ...]
    }]
    """
    ret_tools = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
            continue
        if hasattr(plugin, "get_agent_tools") and ObjectUtils.check_method(plugin.get_agent_tools):
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
    return ret_tools

def get_plugin_remote_entry(plugin_id: str, dist_path: str) -> str:
    """
    获取插件的远程入口地址
    :param plugin_id: 插件 ID
    :param dist_path: 插件的分发路径
    :return: 远程入口地址
    """
    dist_path = dist_path.strip("/")
    path = posixpath.join(
        "plugin",
        "file",
        plugin_id.lower(),
        dist_path,
        "remoteEntry.js",
    )
    if not path.startswith("/"):
        path = "/" + path
    return path

def get_plugin_remotes(running_plugins, pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    获取插件联邦组件列表
    """
    remotes = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if pid and pid != plugin_id:
            continue
        if hasattr(plugin, "get_render_mode"):
            render_mode, dist_path = plugin.get_render_mode()
            if render_mode != "vue":
                continue
            remotes.append({
                "id": plugin_id,
                "url": get_plugin_remote_entry(plugin_id, dist_path),
                "name": plugin.plugin_name,
            })
    return remotes

def get_plugin_auth_providers(running_plugins) -> List[Dict[str, Any]]:
    """
    聚合插件声明的登录认证提供方。

    :return: 插件认证入口列表
    """
    providers: List[Dict[str, Any]] = []
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not plugin.get_state():
            continue
        if not hasattr(plugin, "get_auth_providers") or not ObjectUtils.check_method(plugin.get_auth_providers):
            continue
        try:
            plugin_providers = plugin.get_auth_providers() or []
        except Exception as e:
            logger.error(f"获取插件 {plugin_id} 登录认证提供方出错：{str(e)}")
            continue
        render_mode = None
        dist_path = None
        if hasattr(plugin, "get_render_mode"):
            render_mode, dist_path = plugin.get_render_mode()
        for raw_provider in plugin_providers:
            if not raw_provider or not isinstance(raw_provider, dict):
                continue
            provider = raw_provider.copy()
            provider["type"] = "plugin"
            provider["plugin_id"] = plugin_id
            provider.setdefault("id", f"plugin:{plugin_id}")
            provider.setdefault("name", plugin.plugin_name)
            provider.setdefault("enabled", True)
            if render_mode == "vue" and dist_path:
                provider.setdefault("component", "AuthPage")
                provider["remote"] = {
                    "id": plugin_id,
                    "url": get_plugin_remote_entry(plugin_id, dist_path),
                    "name": plugin.plugin_name,
                }
            providers.append(provider)
    return providers

def get_plugin_sidebar_nav(running_plugins) -> List[Dict[str, Any]]:
    """
    聚合所有已启用 Vue 插件的侧栏导航项（get_sidebar_nav）。
    """
    valid_sections = {"start", "discovery", "subscribe", "organize", "system"}
    valid_permissions = {"subscribe", "discovery", "search", "manage", "admin"}
    items: List[Dict[str, Any]] = []
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not plugin.get_state():
            continue
        if not hasattr(plugin, "get_sidebar_nav") or not ObjectUtils.check_method(plugin.get_sidebar_nav):
            continue
        if not hasattr(plugin, "get_render_mode"):
            continue
        render_mode, _ = plugin.get_render_mode()
        if render_mode != "vue":
            continue
        try:
            nav_list = plugin.get_sidebar_nav()
            if not nav_list:
                continue
            for raw in nav_list:
                if not raw or not isinstance(raw, dict):
                    continue
                nav_key = str(raw.get("nav_key") or raw.get("key") or "main").strip()
                if not nav_key or any(c in nav_key for c in ["/", "?", "#", " "]):
                    logger.warning(f"插件[{plugin_id}]侧栏项 nav_key 无效，已跳过: {nav_key!r}")
                    continue
                title = raw.get("title") or plugin.plugin_name
                icon = raw.get("icon") or "mdi-puzzle"
                section = str(raw.get("section") or "system").lower()
                if section not in valid_sections:
                    section = "system"
                perm = raw.get("permission")
                if perm is not None and str(perm) not in valid_permissions:
                    perm = None
                else:
                    perm = str(perm) if perm is not None else None
                order = raw.get("order", 0)
                try:
                    order = int(order)
                except (TypeError, ValueError):
                    order = 0
                items.append({
                    "plugin_id": plugin_id,
                    "nav_key": nav_key,
                    "title": title,
                    "icon": icon,
                    "section": section,
                    "permission": perm,
                    "order": order,
                })
        except Exception as e:
            logger.error(f"获取插件[{plugin_id}]侧栏导航出错：{str(e)}")
    items.sort(key=lambda x: (x["section"], x["order"], x["plugin_id"], x["nav_key"]))
    return items

def get_plugin_dashboard_meta(running_plugins) -> List[Dict[str, str]]:
    """
    获取所有插件仪表盘元信息
    """
    dashboard_meta = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not hasattr(plugin, "get_dashboard") or not ObjectUtils.check_method(plugin.get_dashboard):
            continue
        try:
            if not plugin.get_state():
                continue
            # 如果是多仪表盘实现
            if hasattr(plugin, "get_dashboard_meta") and ObjectUtils.check_method(plugin.get_dashboard_meta):
                meta = plugin.get_dashboard_meta()
                if meta:
                    dashboard_meta.extend([{
                        "id": plugin_id,
                        "name": m.get("name"),
                        "key": m.get("key"),
                    } for m in meta if m])
            else:
                dashboard_meta.append({
                    "id": plugin_id,
                    "name": plugin.plugin_name,
                    "key": "",
                })
        except Exception as e:
            logger.error(f"获取插件[{plugin_id}]仪表盘元数据出错：{str(e)}")
    return dashboard_meta

def get_plugin_dashboard(running_plugins, pid: str, key: str, user_agent: str = None) -> Optional[schemas.PluginDashboard]:
    """
    获取插件仪表盘
    """

    def __get_params_count(func: Callable):
        """
        获取函数的参数信息
        """
        signature = inspect.signature(func)
        return len(signature.parameters)

    # 获取插件实例
    plugin_instance = running_plugins.get(pid)
    if not plugin_instance:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"插件 {pid} 不存在或未加载")

    # 渲染模式
    render_mode, _ = plugin_instance.get_render_mode()
    # 获取插件仪表板
    try:
        # 检查方法的参数个数
        params_count = __get_params_count(plugin_instance.get_dashboard)
        if params_count > 1:
            dashboard: Tuple = plugin_instance.get_dashboard(key=key, user_agent=user_agent)
        elif params_count > 0:
            dashboard: Tuple = plugin_instance.get_dashboard(user_agent=user_agent)
        else:
            dashboard: Tuple = plugin_instance.get_dashboard()
    except Exception as e:
        logger.error(f"插件 {pid} 调用方法 get_dashboard 出错: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"插件 {pid} 调用方法 get_dashboard 出错: {str(e)}")
    if dashboard is None:
        return None
    if not isinstance(dashboard, (tuple, list)) or len(dashboard) != 3:
        logger.error(f"插件 {pid} 返回的仪表盘数据格式错误")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"插件 {pid} 返回的仪表盘数据格式错误")
    cols, attrs, elements = dashboard
    return schemas.PluginDashboard(
        id=pid,
        name=plugin_instance.plugin_name,
        key=key,
        render_mode=render_mode,
        cols=cols or {},
        attrs=attrs or {},
        elements=elements
    )
