"""插件市场技术依赖的唯一启动组合 owner。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from app.adapters.external.plugin.client import (
    PluginMarketClient,
    PluginMarketTransport,
    PluginPackageSourceClient,
)
from app.adapters.system.plugin.dependency import PluginDependencyInstaller
from app.adapters.system.plugin.health import PluginRuntimeHealth
from app.adapters.system.plugin.package import (
    PluginInstallVersionTarget,
    PluginPackageManager,
)
from app.runtime.extensions.plugin.version import (
    PLUGIN_FALLBACK_VERSION,
    ensure_plugin_version_dir_available,
    migrate_legacy_plugin_layout,
    plugin_version_dirs,
    read_declared_plugin_version,
    register_plugin_version,
    remove_plugin_installed_version,
)
from app.runtime.settings import get_runtime_setting


def _resolve_plugin_install_target(
    plugin_id: str,
    plugin_dir: Path,
    staged_source_dir: Path,
) -> Optional[PluginInstallVersionTarget]:
    """决定已就位的暂存源码应当落盘到插件根目录下的哪个版本子目录。

    只做机械的目标目录决策，不扫描源码写法。声明版本号缺失时沿用平铺布局，不为
    没有版本号的插件强行造版本目录；已装内容是平铺布局且声明版本号与待装版本相同
    时同样留在平铺布局，那是一次原地重装，不该凭空造出版本目录——这两条让今天所有
    平铺插件的重装与刷新路径逐字不变，载荷收据也不会因为多出一个版本目录而改变。
    其余情况需要一个版本目录承载待装内容：仍是平铺布局时先把存量源码原地迁移腾出
    插件根目录，迁移失败直接向上抛，以保住存量源码的可加载性。

    版本目录布局与存量迁移都属于运行时扩展包，适配器层不允许引用，因此这个组合
    只能落在组合根。

    :param plugin_id: 插件ID
    :param plugin_dir: 插件根目录；可能尚不存在
    :param staged_source_dir: 已就位的待装源码目录
    :return: 版本目录名与版本号；沿用平铺布局时为 None
    :raise ValueError: 版本号不是合法目录名，或与已装版本大小写撞名
    :raise PluginLayoutMigrationError: 存量平铺布局迁移到版本目录失败
    """
    incoming_version = read_declared_plugin_version(staged_source_dir / "__init__.py")
    if not incoming_version:
        return None

    flat_init = plugin_dir / "__init__.py"
    if not plugin_version_dirs(plugin_dir) and flat_init.is_file():
        installed_version = read_declared_plugin_version(flat_init) or PLUGIN_FALLBACK_VERSION
        if installed_version == incoming_version:
            return None
        migrate_legacy_plugin_layout(plugin_dir)

    dir_name = ensure_plugin_version_dir_available(plugin_dir, incoming_version)
    return PluginInstallVersionTarget(subdirectory=dir_name, version=incoming_version)


def _register_plugin_install_version(
    plugin_dir: Path, version: str, source: str
) -> Optional[str]:
    """把已落盘的版本目录登记进版本元信息并置为当前版本，返回登记前的当前版本号。

    返回值供安装失败清理据此精确复原当前版本，不必在回滚时靠猜。

    :param plugin_dir: 插件根目录
    :param version: 已落盘的版本号
    :param source: 版本来源标签，如 market、local
    :return: 登记前元信息里的当前版本号；本次登记前没有任何已装版本时为 None
    """
    _, previous_current = register_plugin_version(plugin_dir, version, source)
    return previous_current


def _rollback_plugin_install_version(
    plugin_dir: Path, version: str, previous_current: Optional[str]
) -> None:
    """安装失败时回滚单个版本目录及其元信息登记，不牵连插件的其它已装版本。

    :param plugin_dir: 插件根目录
    :param version: 安装失败需要回滚的版本号
    :param previous_current: 登记本次失败版本之前元信息里的当前版本号
    """
    remove_plugin_installed_version(plugin_dir, version, previous_current)


@dataclass(frozen=True, slots=True)
class PluginMarketComposition:
    """保存插件市场相关 Transport、Client、Package 和 Dependency owner。"""

    transport: PluginMarketTransport
    client: PluginMarketClient
    package: PluginPackageManager
    health: PluginRuntimeHealth
    dependency: PluginDependencyInstaller


_market_client: Optional[PluginMarketClient] = None


def compose_plugin_market(
    *,
    installed_plugins_provider: Callable[[], list[str]],
) -> PluginMarketComposition:
    """一次性构造插件市场技术依赖，供同一 lifespan 内所有用例复用。"""
    global _market_client
    root_path = Path(get_runtime_setting("ROOT_PATH"))
    plugin_root = root_path / "app" / "plugins"
    transport = PluginMarketTransport.get_existing_instance() or PluginMarketTransport()
    client = PluginMarketClient(transport)
    health = PluginRuntimeHealth()
    composition = PluginMarketComposition(
        transport=transport,
        client=client,
        package=PluginPackageManager(
            source=PluginPackageSourceClient(transport),
            plugin_root=plugin_root,
            install_target_resolver=_resolve_plugin_install_target,
            install_version_registrar=_register_plugin_install_version,
            install_version_rollback=_rollback_plugin_install_version,
        ),
        dependency=PluginDependencyInstaller(
            health,
            installed_plugins_provider=installed_plugins_provider,
            plugin_dir=plugin_root,
        ),
        health=health,
    )
    _market_client = client
    return composition


def get_composed_plugin_market_client() -> PluginMarketClient:
    """返回当前 lifespan 由组合根构造的唯一插件市场 Client。"""
    if _market_client is None:
        raise RuntimeError("插件市场 Client 尚未由启动组合根装配")
    return _market_client


def reset_plugin_market_composition() -> None:
    """撤销当前 lifespan 的插件市场 Client 投影。"""
    global _market_client
    _market_client = None
