"""插件声明式扩展点的聚合。

把运行态插件经 provides_* 钩子声明的对象按实例键归集，交给对应的注册中心。聚合发生在
声明层而非分发热路径，因此废弃提示也在这里发出，同一实例只留一次痕迹。
"""
from typing import Any, Dict, List, Optional

from app.foundation.reflection import ObjectUtils
from app.runtime.deprecation.policy import warn as deprecation_warn
from app.runtime.extensions.plugin_instance import matches_plugin
from app.runtime.log import logger


def get_plugin_provided_modules(running_plugins: Dict[str, Any],
                                pid: Optional[str] = None) -> Dict[str, List[Any]]:
    """
    聚合插件经 provides_modules() 声明的系统模块

    只取已启用实例的非空声明，单个实例的钩子异常不影响其余实例。

    :param running_plugins: 运行态插件表 {实例键: plugin}
    :param pid: 插件ID或实例键，为空时聚合全部实例
    :return: {实例键: [模块类或 ProvidedModule, ...]}
    """
    provided: Dict[str, List[Any]] = {}
    # 快照避免聚合期间插件启停造成并发修改
    for key, plugin in dict(running_plugins).items():
        if not matches_plugin(key, pid):
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
            provided[key] = list(modules)
            _warn_mixed_declaration(key, plugin)
        except Exception as err:
            logger.error(f"获取插件 {key} 注册模块出错：{str(err)}")
    return provided


def warn_legacy_module_injection(key: str) -> None:
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
