"""v2 插件生态调用面契约测试。

市场存量插件除 compat 旧路径外，还直接使用一批 canonical 符号
（Chain 类、Oper 旧路径、事件系统、调度器、插件基类 hook）。
这些符号构成事实上的插件 API 面；本文件把该面固化为契约：
任何结构重构必须保持其可导入与关键成员存在，否则会破坏 v2 插件生态。
"""

import importlib

import pytest

from app.runtime.compat.manifest import PACKAGE_EXPORTS, SYMBOL_ALIASES


# 市场插件直接 import 的 Chain 类（按 canonical 路径）。
CHAIN_CONTRACT = {
    "app.chain": ("ChainBase",),
    "app.chain.storage": ("StorageChain",),
    "app.chain.transfer": ("TransferChain",),
    "app.chain.media": ("MediaChain",),
    "app.chain.tmdb": ("TmdbChain",),
    "app.chain.search": ("SearchChain",),
    "app.chain.subscribe": ("SubscribeChain",),
    "app.chain.download": ("DownloadChain",),
    "app.chain.site": ("SiteChain",),
    "app.chain.mediaserver": ("MediaServerChain",),
}

# 插件经旧 db 模块路径使用的 Oper（由 compat manifest 与 sdk/_legacy 承接）。
OPER_LEGACY_CONTRACT = {
    "app.db.site_oper": ("SiteOper",),
    "app.db.systemconfig_oper": ("SystemConfigOper",),
    "app.db.plugindata_oper": ("PluginDataOper",),
    "app.db.transferhistory_oper": ("TransferHistoryOper",),
    "app.db.downloadhistory_oper": ("DownloadHistoryOper",),
    "app.db.subscribe_oper": ("SubscribeOper",),
    "app.db.user_oper": ("UserOper", "get_current_active_user"),
}

# 插件注册事件处理器时使用的事件类型成员。
EVENT_TYPE_MEMBERS = (
    "PluginAction",
    "MessageAction",
    "UserMessage",
    "WebhookMessage",
    "DownloadFileDeleted",
)
CHAIN_EVENT_TYPE_MEMBERS = (
    "TransferRename",
    "TransferIntercept",
)

# v2 插件宿主基类必须保留的 hook 面（PluginManager 按方法名探测）。
PLUGIN_BASE_HOOKS = (
    "init_plugin",
    "get_state",
    "get_command",
    "get_api",
    "get_form",
    "get_page",
    "get_service",
    "get_dashboard",
    "get_dashboard_meta",
    "get_auth_providers",
    "get_module",
    "get_actions",
    "get_render_mode",
    "provides_modules",
    "provides_models",
    "provides_migration_location",
    "get_agent_tools",
    "stop_service",
)


@pytest.mark.parametrize("module_name, symbols", sorted(CHAIN_CONTRACT.items()))
def test_chain_classes_remain_importable(module_name, symbols):
    """插件直接使用的 Chain 类必须保持可导入。"""
    module = importlib.import_module(module_name)
    for symbol in symbols:
        assert hasattr(module, symbol), f"{module_name}.{symbol} 缺失"


def test_chain_classes_still_subclass_chainbase():
    """插件对 Chain 类的继承/实例化依赖 ChainBase 层级关系。"""
    from app.chain import ChainBase
    from app.chain.storage import StorageChain
    from app.chain.transfer import TransferChain

    assert issubclass(StorageChain, ChainBase)
    assert issubclass(TransferChain, ChainBase)


@pytest.mark.parametrize("module_name, symbols", sorted(OPER_LEGACY_CONTRACT.items()))
def test_oper_legacy_paths_remain_importable(module_name, symbols):
    """旧 db 模块路径与其符号必须持续可用。"""
    module = importlib.import_module(module_name)
    for symbol in symbols:
        assert hasattr(module, symbol), f"{module_name}.{symbol} 缺失"


def test_event_system_legacy_path():
    """插件经 app.core.event 注册与发送事件的入口必须保留。"""
    event_module = importlib.import_module("app.core.event")
    for symbol in ("eventmanager", "EventManager", "Event"):
        assert hasattr(event_module, symbol), f"app.core.event.{symbol} 缺失"

    from app.schemas.types import ChainEventType, EventType

    for member in EVENT_TYPE_MEMBERS:
        assert hasattr(EventType, member), f"EventType.{member} 缺失"
    for member in CHAIN_EVENT_TYPE_MEMBERS:
        assert hasattr(ChainEventType, member), f"ChainEventType.{member} 缺失"


def test_scheduler_remains_importable():
    """插件按 app.scheduler.Scheduler 注册后台任务。"""
    module = importlib.import_module("app.scheduler")
    assert hasattr(module, "Scheduler")


def test_plugin_base_hook_surface():
    """_PluginBase 的方法名探测 hook 面必须完整保留。"""
    from app.plugins import _PluginBase

    missing = [hook for hook in PLUGIN_BASE_HOOKS if not hasattr(_PluginBase, hook)]
    assert missing == [], f"_PluginBase 缺失 hook: {missing}"


def test_core_meta_package_exports_resolve():
    """app.core.meta 的包级符号导出必须逐一可解析。"""
    for package_name, exports in PACKAGE_EXPORTS.items():
        package = importlib.import_module(package_name)
        for legacy_name in exports:
            assert getattr(package, legacy_name, None) is not None, (
                f"{package_name}.{legacy_name} 无法解析"
            )


def test_symbol_aliases_resolve_in_full():
    """SYMBOL_ALIASES 声明的旧符号必须在对应模块上全部可取。"""
    failures = []
    for module_name, aliases in SYMBOL_ALIASES.items():
        module = importlib.import_module(module_name)
        for legacy_name in aliases:
            if getattr(module, legacy_name, None) is None:
                failures.append(f"{module_name}.{legacy_name}")
    assert failures == [], f"符号别名解析失败: {failures}"
