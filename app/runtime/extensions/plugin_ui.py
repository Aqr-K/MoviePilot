"""插件前端呈现的聚合。

把运行态插件声明的联邦组件、登录认证入口、侧栏导航和仪表盘归集成前端可直接消费的投影。
呈现侧的口径在这里收敛：导航分区与权限取白名单、联邦入口按插件标识定位源码目录下的构建
产物、仪表盘统一成固定结构，插件只负责声明。

条目的归属标识为实例键，与该实例注册的接口路由前缀一致；只有共用一份构建产物的联邦入口
按插件标识去重。
"""
import inspect
import posixpath
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException
from starlette import status

from app import schemas
from app.foundation.reflection import ObjectUtils
from app.runtime.extensions.plugin_instance import (
    instance_key,
    matches_plugin,
    plugin_id_of,
    split_instance_key,
)
from app.runtime.log import logger

# 侧栏导航允许落位的分区
VALID_NAV_SECTIONS = {"start", "discovery", "subscribe", "organize", "system"}
# 侧栏导航允许声明的可见性权限
VALID_NAV_PERMISSIONS = {"subscribe", "discovery", "search", "manage", "admin"}


def get_plugin_remote_entry(plugin_id: str, dist_path: str) -> str:
    """
    获取插件的远程入口地址

    静态资源存放在插件源码目录，同一插件的全部实例共用一份构建产物，因此入口地址
    取插件标识而非实例键。

    :param plugin_id: 插件 ID 或实例键
    :param dist_path: 插件的分发路径
    :return: 远程入口地址
    """
    dist_path = dist_path.strip("/")
    path = posixpath.join(
        "plugin",
        "file",
        plugin_id_of(plugin_id).lower(),
        dist_path,
        "remoteEntry.js",
    )
    if not path.startswith("/"):
        path = "/" + path
    return path


def get_plugin_remotes(running_plugins: Dict[str, Any],
                       pid: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    聚合插件声明的联邦组件

    联邦入口是插件源码目录下的一份构建产物，同一插件的多个实例只登记一条。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: 联邦组件列表
    """
    remotes = []
    declared_plugin_ids = set()
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for key, plugin in running_plugins_snapshot.items():
        if not matches_plugin(key, pid):
            continue
        try:
            render_hook = getattr(plugin, "get_render_mode", None)
            if render_hook is None:
                continue
            render_mode, dist_path = render_hook()
            if render_mode != "vue":
                continue
            plugin_id = plugin_id_of(key)
            if plugin_id in declared_plugin_ids:
                continue
            declared_plugin_ids.add(plugin_id)
            remotes.append({
                "id": plugin_id,
                "url": get_plugin_remote_entry(plugin_id, dist_path),
                "name": plugin.plugin_name,
            })
        except Exception as e:
            logger.error(f"获取插件[{key}]联邦组件出错：{str(e)}")
    return remotes


def _instance_auth_provider_id(declared_id: Optional[str], key: str) -> str:
    """
    获取登录认证入口在前端列表中的唯一标识

    入口标识由插件声明，同一插件的多个实例声明的是同一个标识，因此分身实例的入口按实例
    标识加以区分；未声明时取实例键。

    :param declared_id: 插件声明的入口标识
    :param key: 声明该入口的实例键
    :return: 入口标识
    """
    if declared_id is None:
        return f"plugin:{key}"
    return instance_key(str(declared_id), split_instance_key(key)[1])


def get_plugin_auth_providers(running_plugins: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    聚合插件声明的登录认证提供方

    只取已启用实例的入口，同一插件的每个实例各出一条：provider 的 plugin_id 为实例键，
    与该实例注册的接口路由一致，入口标识按实例区分使多个实例互不覆盖；remote 指向插件
    源码目录下的联邦入口，按插件标识定位。单个实例的钩子异常只记录日志，不影响其余实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :return: 插件认证入口列表
    """
    providers: List[Dict[str, Any]] = []
    running_plugins_snapshot = dict(running_plugins)
    for key, plugin in running_plugins_snapshot.items():
        try:
            hook = getattr(plugin, "get_auth_providers", None)
            if hook is None or not ObjectUtils.check_method(hook):
                continue
            if not plugin.get_state():
                continue
            plugin_providers = hook() or []
            render_mode = None
            dist_path = None
            render_hook = getattr(plugin, "get_render_mode", None)
            if render_hook is not None:
                render_mode, dist_path = render_hook()
            for raw_provider in plugin_providers:
                if not raw_provider or not isinstance(raw_provider, dict):
                    continue
                provider = raw_provider.copy()
                provider["type"] = "plugin"
                provider["plugin_id"] = key
                provider["id"] = _instance_auth_provider_id(provider.get("id"), key)
                provider.setdefault("name", plugin.plugin_name)
                provider.setdefault("enabled", True)
                if render_mode == "vue" and dist_path:
                    provider.setdefault("component", "AuthPage")
                    provider["remote"] = {
                        "id": plugin_id_of(key),
                        "url": get_plugin_remote_entry(key, dist_path),
                        "name": plugin.plugin_name,
                    }
                providers.append(provider)
        except Exception as e:
            logger.error(f"获取插件[{key}]登录认证提供方出错：{str(e)}")
    return providers


def get_plugin_sidebar_nav(running_plugins: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    聚合所有已启用 Vue 插件的侧栏导航项（get_sidebar_nav）

    同一插件的每个实例各出一条：导航项的 plugin_id 为实例键，与该实例注册的接口路由前缀
    一致，多个实例声明同名 nav_key 时互不覆盖。单个实例的钩子异常只记录日志，不影响其余
    实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :return: 侧栏导航项列表
    """
    items: List[Dict[str, Any]] = []
    running_plugins_snapshot = dict(running_plugins)
    for key, plugin in running_plugins_snapshot.items():
        try:
            hook = getattr(plugin, "get_sidebar_nav", None)
            if hook is None or not ObjectUtils.check_method(hook):
                continue
            render_hook = getattr(plugin, "get_render_mode", None)
            if render_hook is None:
                continue
            if not plugin.get_state():
                continue
            render_mode, _ = render_hook()
            if render_mode != "vue":
                continue
            nav_list = hook()
            if not nav_list:
                continue
            for raw in nav_list:
                if not raw or not isinstance(raw, dict):
                    continue
                nav_key = str(raw.get("nav_key") or raw.get("key") or "main").strip()
                if not nav_key or any(c in nav_key for c in ["/", "?", "#", " "]):
                    logger.warning(f"插件[{key}]侧栏项 nav_key 无效，已跳过: {nav_key!r}")
                    continue
                title = raw.get("title") or plugin.plugin_name
                icon = raw.get("icon") or "mdi-puzzle"
                section = str(raw.get("section") or "system").lower()
                if section not in VALID_NAV_SECTIONS:
                    section = "system"
                perm = raw.get("permission")
                if perm is not None and str(perm) not in VALID_NAV_PERMISSIONS:
                    perm = None
                else:
                    perm = str(perm) if perm is not None else None
                order = raw.get("order", 0)
                try:
                    order = int(order)
                except (TypeError, ValueError):
                    order = 0
                items.append({
                    "plugin_id": key,
                    "nav_key": nav_key,
                    "title": title,
                    "icon": icon,
                    "section": section,
                    "permission": perm,
                    "order": order,
                })
        except Exception as e:
            logger.error(f"获取插件[{key}]侧栏导航出错：{str(e)}")
    items.sort(key=lambda x: (x["section"], x["order"], x["plugin_id"], x["nav_key"]))
    return items


def get_plugin_dashboard_meta(running_plugins: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    聚合所有插件仪表盘元信息

    只取已启用实例的仪表盘，同一插件的每个实例各出一条：条目的 id 为实例键，与该实例注册
    的接口路由前缀一致，多个实例声明同名仪表盘 key 时互不覆盖。单个实例的钩子异常只记录
    日志，不影响其余实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :return: 仪表盘元信息列表
    """
    dashboard_meta = []
    # 创建字典快照避免并发修改
    running_plugins_snapshot = dict(running_plugins)
    for key, plugin in running_plugins_snapshot.items():
        try:
            dashboard_hook = getattr(plugin, "get_dashboard", None)
            if dashboard_hook is None or not ObjectUtils.check_method(dashboard_hook):
                continue
            if not plugin.get_state():
                continue
            # 如果是多仪表盘实现
            meta_hook = getattr(plugin, "get_dashboard_meta", None)
            if meta_hook is not None and ObjectUtils.check_method(meta_hook):
                meta = meta_hook()
                if meta:
                    dashboard_meta.extend([{
                        "id": key,
                        "name": m.get("name"),
                        "key": m.get("key"),
                    } for m in meta if m])
            else:
                dashboard_meta.append({
                    "id": key,
                    "name": plugin.plugin_name,
                    "key": "",
                })
        except Exception as e:
            logger.error(f"获取插件[{key}]仪表盘元数据出错：{str(e)}")
    return dashboard_meta


def get_plugin_dashboard(running_plugins: Dict[str, Any], pid: str, key: str,
                         user_agent: str = None) -> Optional[schemas.PluginDashboard]:
    """
    获取插件仪表盘

    按实例键精确定位，裸插件标识即默认实例的实例键，因此只解析到默认实例，不会串到该插件
    的其他实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 实例键，裸插件标识指向默认实例
    :param key: 仪表盘标识，多仪表盘插件据此区分
    :param user_agent: 请求方 User-Agent，插件据此适配呈现
    :return: 仪表盘数据，插件未返回内容时为 None
    :raises HTTPException: 实例未加载、调用出错或返回数据格式错误
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
