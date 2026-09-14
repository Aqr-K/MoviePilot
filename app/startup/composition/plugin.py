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
from app.runtime.extensions.plugin.readiness import plugin_multi_version_blockers
from app.runtime.extensions.plugin.version import (
    PLUGIN_FALLBACK_VERSION,
    ensure_plugin_version_dir_available,
    migrate_legacy_plugin_layout,
    plugin_version_dirs,
    read_declared_plugin_version,
    register_plugin_version,
    remove_plugin_installed_version,
    resolve_instance_version_dir,
    resolve_plugin_version_dir,
)
from app.runtime.log import logger
from app.runtime.settings import get_runtime_setting
from app.schemas.plugin import PluginInstance


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


def _plugin_expected_versions_after_install(
    plugin_id: str,
    installed_version: str,
    incoming_version: str,
    available_versions: set[str],
) -> set[str]:
    """算出安装完成后本体与各分身实际期望加载的版本集合。

    这是本守卫真正要回答的问题：装完之后会不会有两份源码同时被加载。磁盘上还留着旧
    版本目录只说明它尚未被回收，不能据此阻止一次普通升级——全部实例都跟随当前版本时，
    安装只改变 current，运行期仍然只有一份源码在跑。反过来，只要有实例被钉在旧版本、
    同时又有实例跟随新的 current，并存就是真的会发生。

    绑定事实只存在于运行时的实例表里，安装服务在插件 Runtime 物化之后才会调到这道
    守卫，因此这里用无副作用的 existing-manager 探测，不为一次体检隐式构造运行时。
    尚未物化时只有一个跟随新 current 的默认本体，集合退化为单元素。已物化但绑定查询
    失败则向上抛出：凑不齐绑定就等于判据未知，此时放行等于把未知当成安全。

    钉住的版本目录已经不在磁盘上时按新 current 计入：加载器对同一场景的处置正是回落
    到当前版本，拿一个谁也加载不到的旧版本去判并存只会把一次正常升级拦下来。

    :param plugin_id: 插件ID
    :param installed_version: 当前已装源码声明的版本号
    :param incoming_version: 本次待装源码声明的版本号
    :param available_versions: 安装完成后磁盘上会存在的版本号集合
    :return: 期望加载的版本号集合
    :raise RuntimeError: 运行时已物化但绑定查询失败
    """
    try:
        # 延迟到调用时导入：本模块在 lifespan 里构造插件市场依赖，那一刻插件 Runtime
        # 的应用层提供器尚未发布，顶层导入等于让市场组合依赖一个还不存在的门面
        from app.application.plugin.runtime import get_existing_plugin_manager

        manager = get_existing_plugin_manager()
    except (ImportError, RuntimeError):
        manager = None
    if manager is None:
        return {incoming_version}

    def expected_of(instance: Optional[PluginInstance]) -> str:
        """把一条绑定折算成它装完之后实际会加载的版本号。"""
        if instance is None or not instance.pinned_version:
            return incoming_version
        pinned = instance.pinned_version
        if pinned == installed_version or pinned in available_versions:
            return pinned
        return incoming_version

    try:
        host = manager.get_plugin_version_binding(plugin_id)
        expected_versions = {expected_of(host if host is not None and host.is_host else None)}
        for clone in manager.get_plugin_source_instances(plugin_id) or []:
            expected_versions.add(expected_of(clone))
        return expected_versions
    except Exception as error:  # noqa: BLE001 - 并存判据未知时必须拒绝
        raise RuntimeError(
            f"无法确认插件 {plugin_id} 的版本绑定，拒绝不安全的版本切换：{error}"
        ) from error


def _reject_incompatible_plugin_version_switch(
    plugin_id: str,
    plugin_dir: Path,
    source_dir: Path,
) -> Optional[str]:
    """判定插件从已装版本切换到另一版本能否被安装期接受。

    只在本次声明版本号确实变化时才体检：同版本重新同步是开发闭环的日常操作，不是在装
    另一个版本，不值得为它扫描全部源码。变化时按各实例的版本绑定算出安装完成后真正会
    并存的版本集合——而不是拿磁盘上留着几个版本目录去近似，那会把「旧目录还没回收」
    这件与运行期无关的事误判成并存，把一次普通升级拦下来。集合里只有一个版本时装完仍
    然只有一份源码在跑，无从并存，直接放行。

    确实会并存时才扫描，命中自引用绝对导入或宿主共享声明基类建模即拒绝安装：这两类
    写法在真正的多版本并存下必然失败，把故障从运行期提前到安装时，而不是等到加载时
    才炸开。

    这个组合只能落在组合根——版本目录布局与并存写法体检都属于运行时扩展包，适配器层不得引用，
    只能由组合根装配成端口注入。

    :param plugin_id: 插件ID
    :param plugin_dir: 插件根目录；尚未安装任何源码时不体检
    :param source_dir: 待安装的插件源码目录
    :return: 拒绝说明；无需拒绝时为 None
    """
    # 已装源码要按当前布局解析：插件迁到版本目录布局后根目录不再有 __init__.py，
    # 直接判根目录会让这道守卫从此每次都放行，正好从第二个版本开始永久失效
    installed_init = resolve_plugin_version_dir(plugin_dir) / "__init__.py"
    if not installed_init.is_file():
        return None
    installed_version = read_declared_plugin_version(installed_init)
    incoming_version = read_declared_plugin_version(source_dir / "__init__.py")
    if not installed_version or not incoming_version or installed_version == incoming_version:
        return None
    on_disk = plugin_version_dirs(plugin_dir)
    available_versions = set(on_disk) | {installed_version, incoming_version}
    try:
        expected_versions = _plugin_expected_versions_after_install(
            plugin_id, installed_version, incoming_version, available_versions
        )
    except RuntimeError as error:
        return str(error)
    if len(expected_versions) <= 1:
        return None
    # 只扫真正会被加载的那几份源码：待装内容还没落盘，用它的暂存目录顶替 incoming_version
    source_dirs = [
        on_disk[version]
        for version in sorted(expected_versions)
        if version != incoming_version and version in on_disk
    ]
    source_dirs.append(source_dir)
    blockers = plugin_multi_version_blockers(plugin_id.lower(), source_dirs)
    if not blockers:
        return None
    return (
        f"插件 {plugin_id} 的写法不支持多版本并存，拒绝从 {installed_version} 版本切换到 "
        f"{incoming_version} 版本：" + "；".join(blockers)
    )


def _bound_plugin_directories(plugin_id: str, plugin_root: Path) -> list[Path]:
    """解析一个插件名下全部实例实际会加载的版本目录，供依赖扫描使用。

    依赖清单与 wheels 随源码进了版本目录，按插件根目录或一律按当前版本取清单，
    钉在旧版本的实例装上的依赖就与它实际跑的代码对不上。这里把本体与每个分身的
    绑定各解析一次，得到「这个插件本次真正要被加载的那几份源码」。

    绑定事实只存在于运行时的实例表里，依赖扫描却早于插件 Runtime 物化就可能被调到，
    因此用无副作用的 existing-manager 探测，不为一次依赖扫描隐式构造运行时；探测不到
    或绑定查询失败时回落到磁盘上全部已装版本目录。回落方向刻意偏向多扫：多扫一个
    版本最多多装几个用不上的包，漏扫一个版本则是那个实例直接起不来。出于同样的理由
    分身不按启用位过滤——停用的分身随时可能被重新启用，它那一版的依赖先装着不亏。

    版本目录布局属于运行时扩展包，适配器层不得引用，因此这个组合只能落在组合根。

    :param plugin_id: 插件ID
    :param plugin_root: 插件源码根目录（``app/plugins/<插件ID>``）
    :return: 去重后的源码目录列表；没有任何版本目录的存量平铺布局时为插件根目录本身
    """
    try:
        # 延迟到调用时导入：本模块在 lifespan 里构造插件市场依赖，那一刻插件 Runtime
        # 的应用层提供器尚未发布，顶层导入等于让市场组合依赖一个还不存在的门面
        from app.application.plugin.runtime import get_existing_plugin_manager

        manager = get_existing_plugin_manager()
    except (ImportError, RuntimeError):
        manager = None

    bindings: list[Optional[PluginInstance]] = []
    if manager is not None:
        try:
            host = manager.get_plugin_version_binding(plugin_id)
            bindings.append(host if host is not None and host.is_host else None)
            bindings.extend(manager.get_plugin_source_instances(plugin_id) or [])
        except Exception as error:  # noqa: BLE001 - 读不到绑定就退回全量扫描
            logger.debug(f"读取插件 {plugin_id} 的版本绑定失败，按全部已装版本扫描依赖：{error}")
            bindings = []
    if not bindings:
        on_disk = list(plugin_version_dirs(plugin_root).values())
        return on_disk or ([plugin_root] if plugin_root.is_dir() else [])

    directories: list[Path] = []
    seen: set[Path] = set()
    for binding in bindings:
        directory = resolve_instance_version_dir(plugin_root, binding)
        if not directory.is_dir():
            continue
        resolved = directory.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        directories.append(directory)
    return sorted(directories, key=lambda item: item.name)


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
            version_switch_guard=_reject_incompatible_plugin_version_switch,
        ),
        dependency=PluginDependencyInstaller(
            health,
            installed_plugins_provider=installed_plugins_provider,
            plugin_dir=plugin_root,
            plugin_directories_provider=lambda plugin_id: _bound_plugin_directories(
                plugin_id, plugin_root / plugin_id.lower()
            ),
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
