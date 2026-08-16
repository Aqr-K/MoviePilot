"""模块能力推导。

能力 = 模块对外提供、可被 chain 分发的方法。一个模块提供哪些能力**由运行期实例推导**，
不由 ModuleType 标签声明，也不由源码文本静态扫描得出：

- 标签会撒谎。同一个 ModuleType 同时承担分发路由、服务配置归类、契约归属声明与健康检查
  分类四种职责，一个标签不可能对四种目的都正确，于是出现「声明了识别类型却不实现任何
  识别方法」和「实际是图片族成员却挂着其它类型」两个方向的错配。
- 静态扫描有盲点。方法可以继承自兄弟模块（如 AlistGo 的整套存储契约继承自 Alist），
  只解析类体会把它看成什么都没实现。

从运行期实例推导则两者皆无：拿到的就是分发时真正能调到的那一组方法。

生命周期与基础设施基类提供的方法不是能力：前者是模块契约本身，后者是配置与服务实例
管理的管道，都不参与 chain 分发。
"""
import inspect
from typing import Any, FrozenSet, Set

from app.foundation.reflection import ObjectUtils

# 模块契约方法，所有模块都有，不区分能力
LIFECYCLE_METHODS: FrozenSet[str] = frozenset({
    "init_module", "init_setting", "stop", "test", "get_name", "get_type", "get_subtype",
    "get_priority", "on_config_changed", "get_reload_name", "handle_config_changed",
    # 横切钩子，所有模块按需实现，广播到全体是其本意，不区分能力归属
    "clear_cache", "scheduler_job",
})

# 只接受内建模块提供的能力，外部来源声明这些方法时拒绝注册
#
# 站点索引刻意不向插件开放。这条约束不能靠「不给 indexer 做注册器」来维持：
# provides_modules() 的契约是注册后与内建模块同权参与分发，任何插件模块只要实现
# search_torrents 就会进入 run_module("search_torrents", ...) 的广播，绕过 indexer
# 直接供种。约束必须落在能力面上。
BUILTIN_ONLY_CAPABILITIES: FrozenSet[str] = frozenset({
    "get_search_page_size",
    "refresh_torrents", "async_refresh_torrents",
    "refresh_userdata",
    "search_subtitles", "async_search_subtitles",
    "search_torrents", "async_search_torrents",
})

# 提供管道而非能力的基类，其上定义的方法不计入能力
INFRASTRUCTURE_BASES: FrozenSet[str] = frozenset({
    "object", "ABC", "Generic",
    "ConfigReloadMixin", "_ModuleBase",
    "ServiceBase", "_MessageBase", "_DownloaderBase", "_MediaServerBase",
})


def _declaring_classes(module_cls: type, name: str) -> Set[str]:
    """
    取定义了该属性的类名集合

    :param module_cls: 模块类
    :param name: 属性名
    :return: MRO 中定义了该属性的类名
    """
    return {base.__name__ for base in inspect.getmro(module_cls) if name in vars(base)}


def provided_capabilities(module: Any) -> FrozenSet[str]:
    """
    推导一个模块提供的能力

    :param module: 模块实例或模块类
    :return: 能力方法名集合
    """
    module_cls = module if isinstance(module, type) else type(module)
    capabilities = set()
    for name in dir(module_cls):
        if name.startswith("_") or name in LIFECYCLE_METHODS:
            continue
        declaring = _declaring_classes(module_cls, name)
        if not declaring or declaring <= INFRASTRUCTURE_BASES:
            continue
        try:
            attr = getattr(module, name)
        except Exception:
            continue
        if not callable(attr):
            continue
        try:
            # 空实现的桩方法不构成能力；无法内省的对象按提供处理
            if not ObjectUtils.check_method(attr):
                continue
        except Exception:
            pass
        capabilities.add(name)
    return frozenset(capabilities)
