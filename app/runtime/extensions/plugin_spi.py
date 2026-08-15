"""插件声明式扩展点的聚合。

把运行态插件经 provides_* 钩子声明的对象按插件标识归集，交给对应的注册中心。聚合发生在
声明层而非分发热路径，因此废弃提示也在这里发出，同一插件只留一次痕迹。
"""
from typing import Any, Dict, List, Optional

from app.foundation.reflection import ObjectUtils
from app.runtime.deprecation.policy import warn as deprecation_warn
from app.runtime.log import logger


def get_plugin_provided_modules(running_plugins: Dict[str, Any],
                                pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """
    聚合插件经 provides_modules() 声明的系统模块

    只取已启用插件的非空声明，单个插件的钩子异常不影响其余插件。

    :param running_plugins: 运行态插件表 {plugin_id: plugin}
    :param pid: 插件ID，为空时聚合全部插件
    :return: {plugin_id: [模块类或 ProvidedModule, ...]}
    """
    provided: Dict[str, List[Any]] = {}
    # 快照避免聚合期间插件启停造成并发修改
    for plugin_id, plugin in dict(running_plugins).items():
        if pid and pid != plugin_id:
            continue
        hook = getattr(plugin, "provides_modules", None)
        if hook is None or not ObjectUtils.check_method(hook):
            continue
        try:
            if not plugin.get_state():
                continue
            modules = hook() or []
            if not modules:
                continue
            provided[plugin_id] = list(modules)
            _warn_mixed_declaration(plugin_id, plugin)
        except Exception as err:
            logger.error(f"获取插件 {plugin_id} 注册模块出错：{str(err)}")
    return provided


def warn_legacy_module_injection(plugin_id: str) -> None:
    """
    就插件使用 get_module() 胁持系统模块发出废弃提示

    :param plugin_id: 插件ID
    """
    deprecation_warn("plugin.get_module", context=plugin_id)


def _warn_mixed_declaration(plugin_id: str, plugin: Any) -> None:
    """
    提示插件同时使用了两种模块声明方式

    两者都会生效且互不去重，同名方法上 get_module() 的实现优先于注册模块。

    :param plugin_id: 插件ID
    :param plugin: 插件实例
    """
    legacy = getattr(plugin, "get_module", None)
    if legacy is None or not ObjectUtils.check_method(legacy):
        return
    deprecation_warn("plugin.get_module", context=f"{plugin_id}（与 provides_modules() 并存）")
