"""插件声明式扩展点的聚合。

把运行态插件经声明钩子交出的系统模块、交互命令、接口路由、定时服务、工作流动作和智能体
工具按实例键归集，交给对应的注册中心。聚合发生在声明层而非分发热路径，因此废弃提示也在
这里发出，同一实例只留一次痕迹。

单个实例的钩子异常只记录日志，不影响其余实例的聚合结果。
"""
import threading
from typing import Any, Dict, List, Optional

from app.foundation.reflection import ObjectUtils
from app.runtime.deprecation.policy import warn as deprecation_warn
from app.runtime.extensions.contract import verify_agent_tool_contract
from app.runtime.extensions.module_manager import ProvidedModule
from app.runtime.extensions.plugin_instance import matches_plugin
from app.runtime.log import logger
from app.schemas.types import ModuleType

# 按类型细分的模块声明钩子与其期望的模块类型
TYPED_MODULE_HOOKS: Dict[str, ModuleType] = {
    "provides_downloaders": ModuleType.Downloader,
    "provides_mediaservers": ModuleType.MediaServer,
    "provides_notifications": ModuleType.Notification,
    "provides_data_sources": ModuleType.MediaRecognize,
    "provides_storages": ModuleType.Storage,
}

# 智能体工具注册表的构建重试上限，插件状态持续变化时据此有界失败
AGENT_TOOLS_BUILD_MAX_ATTEMPTS = 3

# 智能体工具注册表缓存，插件启停或配置生效时主动失效
_agent_tools_cache: Dict[str, List[Dict[str, Any]]] = {}
_agent_tools_cache_lock = threading.Lock()
_agent_tools_revision: int = 0


def _collect_declarations(running_plugins: Dict[str, Any],
                          pid: Optional[str],
                          hook_name: str,
                          subject: str) -> Dict[str, List[Any]]:
    """
    按实例键归集一个声明钩子的返回值

    只取已启用实例的非空声明，单个实例的钩子异常只记录日志，不影响其余实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :param hook_name: 声明钩子的方法名
    :param subject: 声明内容的名称，用于日志
    :return: {实例键: [声明, ...]}
    """
    collected: Dict[str, List[Any]] = {}
    # 快照避免聚合期间插件启停造成并发修改
    for key, plugin in dict(running_plugins).items():
        if not matches_plugin(key, pid):
            continue
        hook = getattr(plugin, hook_name, None)
        if hook is None:
            continue
        try:
            # 钩子可实现性的判定要连同调用一起隔离，插件给出无法内省的对象时只跳过该实例
            if not ObjectUtils.check_method(hook):
                continue
            if not plugin.get_state():
                continue
            declared = hook() or []
            if not declared:
                continue
            collected.setdefault(key, []).extend(declared)
        except Exception as err:
            logger.error(f"获取插件 {key} {subject}出错：{str(err)}")
    return collected


def get_plugin_provided_modules(running_plugins: Dict[str, Any],
                                pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """
    聚合插件声明的系统模块

    收 provides_modules() 的通用声明，以及 provides_downloaders() 等按类型细分的声明；
    后者转成带期望类型的 ProvidedModule，由模块管理器在契约校验之外追加类型校验。
    只取已启用实例的非空声明，单个实例的钩子异常不影响其余实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: {实例键: [模块类或 ProvidedModule, ...]}
    """
    provided = _collect_declarations(running_plugins, pid, "provides_modules", "注册模块")
    for hook_name, module_type in TYPED_MODULE_HOOKS.items():
        typed = _collect_declarations(running_plugins, pid, hook_name, f"{hook_name} 声明的模块")
        for key, modules in typed.items():
            provided.setdefault(key, []).extend(
                _as_typed_declaration(module, module_type) for module in modules
            )
    for key in provided:
        plugin = running_plugins.get(key)
        if plugin is not None:
            _warn_mixed_declaration(key, plugin)
    return provided


def _as_typed_declaration(module: Any, module_type: ModuleType) -> ProvidedModule:
    """
    给一个模块声明附上期望的模块类型

    声明自带期望类型时保持原样，使插件可以自行指定更精确的判定。

    :param module: 模块类或 ProvidedModule 声明
    :param module_type: 期望的模块类型
    :return: 带期望类型的 ProvidedModule 声明
    """
    if isinstance(module, ProvidedModule):
        if module.expected_type is not None:
            return module
        return ProvidedModule(
            module_cls=module.module_cls,
            module_id=module.module_id,
            factory=module.factory,
            expected_type=module_type,
        )
    return ProvidedModule(module_cls=module, expected_type=module_type)


def get_plugin_provided_channel_capabilities(running_plugins: Dict[str, Any],
                                             pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """
    聚合插件经 provides_channel_capabilities() 声明的渠道能力

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: {实例键: [ChannelCapabilities, ...]}
    """
    return _collect_declarations(running_plugins, pid, "provides_channel_capabilities", "注册渠道能力")


def get_plugin_modules(running_plugins: Dict[str, Any],
                       pid: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
    """
    聚合插件经 get_module() 注入的系统模块方法

    以实例键为键，同一插件的多个实例各占一条，互不覆盖。
    {
        (实例键, 插件名称): {
            method: function
        }
    }

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: {(实例键, 插件名称): {方法名: 方法}}
    """
    ret_modules = {}
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not matches_plugin(plugin_id, pid):
            continue
        if hasattr(plugin, "get_module") and ObjectUtils.check_method(plugin.get_module):
            try:
                if not plugin.get_state():
                    continue
                plugin_module = plugin.get_module() or []
                if plugin_module:
                    _warn_legacy_module_injection(plugin_id)
                ret_modules[(plugin_id, plugin.get_name())] = plugin_module
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} 模块出错：{str(e)}")
    return ret_modules


def get_plugin_commands(running_plugins: Dict[str, Any],
                        pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的交互命令

    [{
        "cmd": "/xx",
        "event": EventType.xx,
        "desc": "xxxx",
        "data": {},
        "pid": "声明该命令的实例键",
    }]

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 命令列表
    """
    ret_commands = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not matches_plugin(plugin_id, pid):
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


def get_plugin_apis(running_plugins: Dict[str, Any],
                    pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的接口路由

    路由路径以声明来源的实例键为前缀，同一插件的多个实例各自占用独立路径。
    [{
        "path": "/xx",
        "endpoint": self.xxx,
        "methods": ["GET", "POST"],
        "summary": "API名称",
        "description": "API说明",
        "allow_anonymous": false
    }]

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 接口路由列表
    """
    ret_apis = []
    if pid:
        plugins = {key: plugin for key, plugin in running_plugins.items()
                   if matches_plugin(key, pid)}
    else:
        plugins = running_plugins
    for plugin_id, plugin in plugins.items():
        if not matches_plugin(plugin_id, pid):
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


def get_plugin_services(running_plugins: Dict[str, Any],
                        pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的定时服务

    [{
        "id": "服务ID",
        "name": "服务名称",
        "trigger": "触发器：cron、interval、date、CronTrigger.from_crontab()",
        "func": self.xxx,
        "kwargs": {} # 定时器参数,
        "func_kwargs": {} # 方法参数,
        "pid": "声明该服务的实例键"
    }]

    同一插件的多个实例各自声明同名服务，pid 携带声明来源的实例键，调用方据此区分。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 服务列表
    """
    ret_services = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not matches_plugin(plugin_id, pid):
            continue
        if hasattr(plugin, "get_service") and ObjectUtils.check_method(plugin.get_service):
            try:
                if not plugin.get_state():
                    continue
                services = plugin.get_service() or []
                for service in services:
                    if not service:
                        continue
                    ret_services.append({**service, "pid": plugin_id})
            except Exception as e:
                logger.error(f"获取插件 {plugin_id} 服务出错：{str(e)}")
    return ret_services


def get_plugin_actions(running_plugins: Dict[str, Any],
                       pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的工作流动作

    [{
        "plugin_id": "声明该动作的实例键",
        "plugin_name": "插件名称",
        "actions": [{
            "id": "动作ID",
            "name": "动作名称",
            "func": self.xxx,
            "kwargs": {} # 需要附加传递的参数
        }]
    }]

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 动作分组列表
    """
    ret_actions = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for plugin_id, plugin in running_plugins_snapshot.items():
        if not matches_plugin(plugin_id, pid):
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


def get_plugin_agent_tools(running_plugins: Dict[str, Any],
                           pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的智能体工具

    结果按筛选条件缓存，缓存在插件启停或配置生效时失效。构建期间注册表版本变化说明快照
    已过期，重新读取；持续变化时有界失败，不阻塞调用线程。

    [{
        "plugin_id": "声明该工具的实例键",
        "plugin_name": "插件名称",
        "tools": [ToolClass1, ToolClass2, ...]
    }]

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 工具分组列表
    :raises RuntimeError: 注册表持续变化，无法建立当前快照
    """
    cache_key = pid or "__all__"
    for _attempt in range(AGENT_TOOLS_BUILD_MAX_ATTEMPTS):
        with _agent_tools_cache_lock:
            cache_revision = _agent_tools_revision
            cached_tools = _agent_tools_cache.get(cache_key)
        if cached_tools is not None:
            return _copy_plugin_agent_tools(cached_tools)

        ret_tools = []
        # 创建字典快照避免并发修改
        running_plugins_snapshot = dict(running_plugins)
        declared = _collect_declarations(
            running_plugins_snapshot, pid, "provides_agent_tools", "注册智能体工具")
        for plugin_id, plugin in running_plugins_snapshot.items():
            if not matches_plugin(plugin_id, pid):
                continue
            tools = _verified_agent_tools(plugin_id, declared.get(plugin_id, []))
            if hasattr(plugin, "get_agent_tools") and ObjectUtils.check_method(
                plugin.get_agent_tools
            ):
                try:
                    if not plugin.get_state():
                        continue
                    legacy_tools = plugin.get_agent_tools() or []
                    if legacy_tools:
                        _warn_legacy_agent_tools(plugin_id)
                        tools = tools + list(legacy_tools)
                except Exception as e:
                    logger.error(f"获取插件 {plugin_id} 智能体工具出错：{str(e)}")
            if tools:
                ret_tools.append({
                    "plugin_id": plugin_id,
                    "plugin_name": plugin.plugin_name,
                    "tools": tools
                })
        with _agent_tools_cache_lock:
            if cache_revision != _agent_tools_revision:
                # 插件状态在注册表构建期间发生变化，重新读取以避免写回过期快照。
                continue
            _agent_tools_cache[cache_key] = _copy_plugin_agent_tools(ret_tools)
            return ret_tools
    raise RuntimeError("插件工具注册表持续变化，无法建立当前快照")


def clear_plugin_agent_tools_cache() -> None:
    """
    清空插件智能体工具注册表缓存并推进版本号
    """
    global _agent_tools_revision
    with _agent_tools_cache_lock:
        _agent_tools_cache.clear()
        _agent_tools_revision += 1


def get_plugin_agent_tools_revision() -> int:
    """
    获取插件智能体工具注册表版本号

    :return: 版本号，调用方据此判断本地工具快照是否仍然有效
    """
    with _agent_tools_cache_lock:
        return _agent_tools_revision


def _copy_plugin_agent_tools(tools_info: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    复制插件智能体工具注册信息，避免调用方修改缓存内容

    :param tools_info: 工具分组列表
    :return: 工具分组列表的副本
    """
    return [
        {
            **plugin_info,
            "tools": list(plugin_info.get("tools", [])),
        }
        for plugin_info in tools_info
    ]


def _verified_agent_tools(key: str, tools: List[Any]) -> List[Any]:
    """
    过滤出满足工具契约的智能体工具类

    不合契约的工具在注册阶段就被拒绝，而不是等到智能体实际调用时才失败。

    :param key: 实例键
    :param tools: 声明的工具类列表
    :return: 通过校验的工具类列表
    """
    verified: List[Any] = []
    for tool in tools:
        passed, reasons = verify_agent_tool_contract(tool)
        if not passed:
            name = getattr(tool, "__name__", tool)
            logger.warning(f"插件 {key} 声明的智能体工具 {name} 未通过契约校验，拒绝注册："
                           f"{'；'.join(reasons)}")
            continue
        verified.append(tool)
    return verified


def _warn_legacy_agent_tools(key: str) -> None:
    """
    就插件使用 get_agent_tools() 声明智能体工具发出废弃提示

    :param key: 实例键
    """
    deprecation_warn("plugin.get_agent_tools", context=key)


def _warn_legacy_module_injection(key: str) -> None:
    """
    就插件使用 get_module() 胁持系统模块发出废弃提示

    :param key: 实例键
    """
    deprecation_warn("plugin.get_module", context=key)


def _warn_mixed_declaration(key: str, plugin: Any) -> None:
    """
    提示插件同时使用了两种模块声明方式

    两者都会生效且互不去重，同名方法上 get_module() 的实现优先于注册模块。

    :param key: 实例键
    :param plugin: 插件实例
    """
    legacy = getattr(plugin, "get_module", None)
    if legacy is None or not ObjectUtils.check_method(legacy):
        return
    deprecation_warn("plugin.get_module", context=f"{key}（与 provides_modules() 并存）")
