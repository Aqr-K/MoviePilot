"""插件宿主运行时依赖聚合与构造。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from app.foundation.crypto import RSAUtils
from app.foundation.version import compare_version
from app.runtime.events import eventmanager
from app.runtime.extensions.plugin.access import PluginAccessPolicy
from app.runtime.extensions.plugin.admission import PluginMutationAdmission
from app.runtime.extensions.plugin.binding import (
    PluginVersionBinding,
    PluginVersionInventory,
)
from app.runtime.extensions.plugin.catalog import PluginCatalogFacade
from app.runtime.extensions.plugin.classification import PluginClassificationRegistry
from app.runtime.extensions.plugin.clone import PluginCloneService
from app.runtime.extensions.plugin.contracts import supports_plugin_hook
from app.runtime.extensions.plugin.database import PluginDatabase
from app.runtime.extensions.plugin.dependency import PluginDependencyService
from app.runtime.extensions.plugin.lifecycle import PluginLifecycle
from app.runtime.extensions.plugin.loader import PluginLoader
from app.runtime.extensions.plugin.loglevel import PluginLogLevelControl
from app.runtime.extensions.plugin.metadata import PluginMetadataMapper
from app.runtime.extensions.plugin.monitor import PluginMonitorController
from app.runtime.extensions.plugin.paths import PluginPathResolver
from app.runtime.extensions.plugin.projection import PluginProjection
from app.runtime.extensions.plugin.registry import PluginRegistry
from app.runtime.extensions.plugin.storage import (
    PluginConfigStore,
    PluginInstanceDirectory,
    PluginInstanceStore,
    PluginStorage,
)
from app.runtime.extensions.plugin.sync import (
    LocalPluginSyncService,
    PluginSyncService,
)
from app.runtime.extensions.plugin.system import PluginSystemServices
from app.runtime.extensions.plugin.target import PluginDefaultTargetControl
from app.runtime.extensions.plugin.tools import PluginToolCatalog
from app.schemas.plugin import PluginInstance
from app.schemas.types import SystemConfigKey


class PluginRuntimeHost(Protocol):
    """声明运行时 owner 回调宿主生命周期门面的最小合同。"""

    def reload_plugin(self, plugin_id: str) -> Any:
        """重载指定插件。"""
        ...

    def remove_plugin(self, plugin_id: str) -> Any:
        """移除指定插件运行实例。"""
        ...

    @staticmethod
    def get_plugin_remote_entry(plugin_id: str, page: str) -> str:
        """构造插件远程页面入口。"""
        ...

    def _run_file_watcher(self) -> None:
        """运行插件文件监控循环。"""
        ...

    def get_plugins_from_market(
        self,
        market: str,
        package_version: Optional[str] = None,
        force: bool = False,
    ) -> Optional[list[Any]]:
        """读取指定市场目录。"""
        ...

    async def async_get_plugins_from_market(
        self,
        market: str,
        package_version: Optional[str] = None,
        force: bool = False,
    ) -> Optional[list[Any]]:
        """异步读取指定市场目录。"""
        ...


PluginCatalogFactory = Callable[[Callable[..., Any]], Any]
PluginImportService = Callable[..., None]
PluginRemoteEntryBuilder = Callable[[str, str], str]


@dataclass(frozen=True, slots=True)
class PluginRuntimeEnvironment:
    """保存由组合根提供的插件运行时外部端口。"""

    plugins_root: Path
    storage: Callable[[], PluginStorage]
    instance_directory: Callable[[], PluginInstanceDirectory]
    system: Callable[[], PluginSystemServices]
    database: Callable[[], PluginDatabase]
    catalog_factory: PluginCatalogFactory
    import_preparer: PluginImportService
    import_scanner: PluginImportService
    auth_level: Callable[[], int]
    remote_entry: PluginRemoteEntryBuilder
    development: Callable[[], bool]
    logger: Any
    # 默认调用目标的置位与清除必须在库层一个事务内清旧置新，因而由组合根直接给出
    # 原子写入端口，不经过按实例逐行读写的实例表端口
    set_default_target: Callable[[str, str], bool]
    clear_default_target: Callable[[str], None]
    # 版本切换后要重建该实例的定时任务、命令与动态路由：新版本声明的这三样都可能与
    # 旧版本不同，不刷新就会留下指向已停实例的旧注册。刷新动作落在 Application 层，
    # 运行时扩展包不得反向 import，因此只能由组合根注入；未注入时静默跳过，供裸运行
    # 时与单元测试构造一个不带宿主注册面的 Runtime
    refresh_registrations: Callable[[str], None] | None = None


@dataclass(frozen=True, slots=True)
class PluginRuntime:
    """聚合一个 PluginManager 生命周期内唯一的职责 owner。"""

    registry: PluginRegistry
    instances: PluginInstanceStore
    configs: PluginConfigStore
    access: PluginAccessPolicy
    catalog: PluginCatalogFacade
    paths: PluginPathResolver
    local_sync: LocalPluginSyncService
    monitor: PluginMonitorController
    admission: PluginMutationAdmission
    dependencies: PluginDependencyService
    loader: PluginLoader
    tools: PluginToolCatalog
    lifecycle: PluginLifecycle
    metadata: PluginMetadataMapper
    sync: PluginSyncService
    clone: PluginCloneService
    version_inventory: PluginVersionInventory
    version_binding: PluginVersionBinding
    log_level: PluginLogLevelControl
    default_target: PluginDefaultTargetControl
    projection: PluginProjection
    classification: PluginClassificationRegistry
    recent_local_sync: dict[str, float]
    system: Callable[[], PluginSystemServices]


def _stop_plugin_for_version_binding(
    lifecycle: PluginLifecycle,
    plugin_id: str,
) -> bool:
    """只在旧实例完全收敛后才结束它，并把结果显式返回给版本绑定服务。

    ``PluginLifecycle.stop`` 为兼容旧调用方保留了无返回值 ABI，并且采用强制 finalize
    语义——它会在 ``stop_service`` 失败时照样把实例摘掉。版本切换不能把一个没停干净的
    实例当成已停止：后续启动会覆盖注册表，旧实例留下的定时任务与事件订阅从此再没有
    句柄能停。因此这里改走两阶段生命周期端口，quiesce 成功才允许 finalize。

    :param lifecycle: 生命周期 owner
    :param plugin_id: 待停止的实例 ID
    :return: 旧实例是否已经完全停止
    """
    if not lifecycle.quiesce(plugin_id):
        return False
    return bool(lifecycle.finalize(plugin_id))


def _plugin_package_write_probe(host: PluginRuntimeHost) -> Callable[[str], bool]:
    """把宿主的包写入抑制窗口适配成「安装是否在途」判据。

    包写入窗口正是插件目录内容会被换入换出的那段时间，此刻切版本可能落到一份写了
    一半的源码上，因此拒绝切换比接受它更便宜。窗口在文件事件收敛前会多保留几秒，
    判据因而偏保守——多拒绝几秒钟的切换请求，而不是放进一次撞上安装的切换。

    宿主没有提供这个能力时（裸运行时、单元测试替身）返回恒假：那种接线根本没有安装
    流程，按在途处理会让版本切换永远打不开。

    注意这只是一次读取，不是互斥：探测之后到真正启动之间仍可能开始一次安装。真正的
    互斥需要包写入锁，那属于版本回收那一层要解决的问题。

    :param host: 插件宿主生命周期门面
    :return: 按插件 ID 判定安装是否在途的函数
    """
    suppressed = getattr(host, "is_plugin_monitor_suppressed", None)
    if not callable(suppressed):
        return lambda _plugin_id: False
    return lambda plugin_id: bool(suppressed(plugin_id))


def build_plugin_runtime(
    host: PluginRuntimeHost,
    environment: PluginRuntimeEnvironment,
    *,
    tool_build_max_attempts: int,
) -> PluginRuntime:
    """按依赖顺序构造唯一插件运行时，各业务能力仍由对应 owner 实现。"""
    registry = PluginRegistry()
    instances = PluginInstanceStore(
        storage=environment.storage,
        directory=environment.instance_directory,
    )
    configs = PluginConfigStore(
        storage=environment.storage,
        database=environment.database,
        plugin_exists=lambda plugin_id: bool(registry.classes.get(plugin_id)),
    )
    access = PluginAccessPolicy(
        auth_level=environment.auth_level,
        verify_keys=RSAUtils.verify_rsa_keys,
        log=environment.logger,
    )

    def host_pinned_version(plugin_id: str) -> Optional[str]:
        """读取源插件本体钉住的版本号，未登记或跟随当前版本时为 None。"""
        host_instance = instances.get_host(plugin_id)
        return host_instance.pinned_version if host_instance is not None else None

    loader = PluginLoader(
        plugins_root=environment.plugins_root,
        import_preparer=environment.import_preparer,
        import_scanner=environment.import_scanner,
        log=environment.logger,
        host_binding=host_pinned_version,
    )
    tools = PluginToolCatalog(max_attempts=tool_build_max_attempts)
    classification = PluginClassificationRegistry(environment.logger)

    def refresh_classification(plugin_id: str, instance: Any) -> None:
        """读取插件当前媒体来源声明并替换其分类扩展注册。"""
        classification.remove(plugin_id)
        declarations = (
            instance.get_media_source() or []
            if supports_plugin_hook(instance, "get_media_source")
            else []
        )
        classification.replace(plugin_id, declarations)

    def load_plugins(
        plugin_id: Optional[str],
        loadable_plugins: list[str],
        validator: Callable[[Any], bool],
        version: Optional[str] = None,
    ) -> list[Any]:
        """加载物理插件或虚拟实例，并保持持久化实例顺序。

        带具体实例 ID 的定向装载同样认启用位。实例存储的读取口刻意返回全部在册行
        （含停用的），加载器在收到具体插件 ID 时也只按这个 ID 找目录、不看可装载
        清单；两处叠在一起，源码变更触发的实例树重载、按 ID 发起的重载就会绕过启用
        判据，把用户停用的实例又拉起来跑到下次重启。

        ``version`` 只在按单个分身实例 ID 加载时生效，供版本切换失败后以某个具体版本
        重试；批量加载时各实例一律按自身绑定解析，一个全局版本号对不同插件没有意义。
        本体不走这个形参——它的源码目录由 ``loader.load`` 按持久化绑定解析，切换时
        锚定值已经先落了盘。
        """
        if plugin_id:
            instance = instances.get(plugin_id)
            if instance:
                if not instance.is_enabled:
                    return []
                return loader.load_instance(instance, validator, version=version)
            if not any(
                loadable.casefold() == plugin_id.casefold()
                for loadable in loadable_plugins
            ):
                return []
            return loader.load(plugin_id, loadable_plugins, validator)
        plugins = loader.load(None, loadable_plugins, validator)
        # 只装载启用的配置：停用的分身仍登记在册、卡片可见，但不该被实例化
        for instance in instances.enabled().values():
            plugins.extend(loader.load_instance(instance, validator))
        return plugins

    lifecycle = PluginLifecycle(
        classes=registry.classes,
        running=registry.running,
        load_plugins=load_plugins,
        # 本体的装载判据归口到实例表的启用位；安装清单只回答「包在不在磁盘上」，
        # 它同时兼任运行开关时，「装着但先不跑」根本没有地方可以表达
        loadable_plugins=lambda: list(instances.enabled_hosts()),
        plugin_config=configs.read,
        auth_checker=lambda plugin: access.check(plugin),
        clear_modules=loader.clear_modules,
        clear_tools=tools.clear,
        enable_events=eventmanager.enable_event_handler,
        disable_events=eventmanager.disable_event_handler,
        runtime_status_writer=registry.set_runtime_status,
        database=environment.database,
        log=environment.logger,
        event_sender=eventmanager.send_event,
        refresh_classification=refresh_classification,
        remove_classification=classification.remove,
    )
    metadata = PluginMetadataMapper(
        plugin_instance=registry.instance,
        plugin_class=registry.plugin_class,
        annotate_system_version=lambda info: environment.system().annotate_system_version(
            info
        ),
        is_package_compatible=lambda info, version: environment.system().is_package_compatible(
            info,
            version,
        ),
        auth_checker=lambda plugin, source: access.check(plugin, source),
        version_compare=lambda source, comparison, target: (
            compare_version(source, comparison, target) is True
        ),
        log=environment.logger,
    )
    catalog = PluginCatalogFacade(
        classes=lambda: registry.classes,
        running=lambda: registry.running,
        storage=environment.storage,
        system=environment.system,
        market_catalog=lambda: environment.catalog_factory(metadata.map),
        market_loader=lambda market, package_version=None, force=False: (
            host.get_plugins_from_market(market, package_version, force)
        ),
        async_market_loader=lambda market, package_version=None, force=False: (
            host.async_get_plugins_from_market(
                market,
                package_version,
                force,
            )
        ),
        map_plugin=lambda **kwargs: metadata.map(
            plugin_id=kwargs["pid"],
            plugin_info=kwargs["plugin_info"],
            market=kwargs["market"],
            installed_plugins=kwargs["installed_apps"],
            add_time=kwargs["add_time"],
            package_version=kwargs.get("package_version"),
        ),
        auth_checker=lambda **kwargs: access.check(**kwargs),
        plugin_attr=lambda plugin_id, attribute: getattr(
            registry.instance(plugin_id),
            attribute,
            None,
        ),
        plugin_instance=instances.get,
        plugin_instances=instances.all,
        host_instances=instances.all_hosts,
        runtime_status=registry.runtime_status,
        log=environment.logger,
    )
    def version_binding_of(plugin_id: str) -> Optional[PluginInstance]:
        """读取该 ID 对应实例的版本绑定，分身优先、回落到源插件本体。

        只查分身会让本体恒为空，静态资源随之按当前版本解析，而代码已按本体钉住的
        版本加载——同一个插件的资源与代码分处两个版本目录。

        :param plugin_id: 实例 ID 或源插件 ID
        :return: 该实例的绑定记录；两侧都没有登记时为 None
        """
        return instances.get(plugin_id) or instances.get_host(plugin_id)

    paths = PluginPathResolver(
        runtime_root=environment.plugins_root,
        running=lambda: registry.running,
        system=environment.system,
        strict_system_version=lambda: not environment.development(),
        log=environment.logger,
        get_instance=version_binding_of,
    )
    recent_local_sync: dict[str, float] = {}
    local_sync = LocalPluginSyncService(
        installed_plugins=lambda: environment.storage().read(
            SystemConfigKey.UserInstalledPlugins
        ) or [],
        candidate=lambda plugin_id: environment.system().local_candidate(plugin_id),
        system=environment.system,
        recent_sync=recent_local_sync,
        log=environment.logger,
    )
    dependencies = PluginDependencyService(
        system=environment.system,
        # 分类结果会被逐个 start()，因此两层都只能给出应当装载的那一部分
        instances=instances.enabled,
        loadable_hosts=lambda: set(instances.enabled_hosts()),
        registry=registry,
        log=environment.logger,
    )
    sync = PluginSyncService(
        frozen=lambda: environment.system().is_frozen(),
        installed_plugins=lambda: environment.storage().read(
            SystemConfigKey.UserInstalledPlugins
        ) or [],
        online_plugins=catalog.online,
        # 启动恢复必须保留本地仓库扫描失败，不能把异常降级为空候选后
        # 再从在线市场下载覆盖当前载荷。
        local_plugins=lambda: catalog.local_repository(raise_errors=True),
        merge_plugins=lambda higher, base, _markets: catalog.merge(higher, base),
        plugin_exists=catalog.exists,
        install=lambda plugin_id, repo_url, force, startup_token: environment.system().install_plugin(
            plugin_id=plugin_id,
            repo_url=repo_url,
            force=force,
            startup_token=startup_token,
        ),
        runtime_status_writer=registry.set_runtime_status,
        log=environment.logger,
    )

    def source_plugin_id(plugin_id: str) -> str:
        """把虚拟实例归一到持久化的物理源码插件。"""
        instance = instances.get(plugin_id)
        return instance.source_plugin_id if instance else plugin_id

    def plugin_registered(plugin_id: str) -> bool:
        """判断插件是否在册：装过（安装清单里有）或留有持久化的实例行。

        默认调用目标与实例日志等级这两个管理接口问的都是「这个插件还在不在册、能不能
        被管理」，因此共用这一个判据，而不能绑在运行期类注册表上：启动只把启用中的
        本体与分身装进注册表，某插件的全部实例停用后重启，注册表里就没有它的类了，
        但它的安装记录与实例行都还在。绑在注册表上等于说「停用即不存在」，而停用不是
        卸载——在册的实例必须仍然可见、可管理，否则用户再也无法把它重新指回默认调用
        目标，也调不出它的日志等级设置，而那份设置正是排查它为什么被停用时要看的。

        「当前是否装载」是另一个问题，由各自的端口回答：插件配置读写看类注册表，
        分身建号与安装前置看包在不在磁盘上，都不走这里。

        :param plugin_id: 插件 ID
        :return: 该插件是否在册
        """
        if instances.get_host(plugin_id) is not None:
            return True
        if instances.for_source(plugin_id):
            return True
        installed = environment.storage().read(
            SystemConfigKey.UserInstalledPlugins
        ) or []
        return plugin_id in installed

    def instance_id_taken(instance_id: str) -> bool:
        """判断一个候选实例 ID 是否已被占用。

        创建分身的判存与自动分配后缀共用这一个判据，自动分配因此不可能挑中一个手填
        时会被拒绝的 ID。四条依据各自覆盖一类占用者，缺一条就会让新分身顶掉一个真实
        存在的插件身份：

        * 类注册表——当前已装载的本体与分身；
        * 实例行——含已停用的分身与本体，它们的配置还留在行上，不是空位；
        * 安装清单——装过但此刻未装载的物理插件；
        * 插件包目录——卸载不删源码，磁盘上因此会留下不在前三者里的插件包，占了它的
          号会让那个插件以后再也装不回来（实例行的归属列对不上，写入直接被拒）。

        判存不能只看运行态：源插件本次加载失败时，已有的同名分身会被判成「不存在」
        而放行，随后它的描述符被覆盖，再在回滚里连同配置一起删掉。``catalog.exists``
        不足以充当磁盘判据——它要从**运行中**的实例上取版本号，未装载的插件包一律
        报告不存在，因而这里直接看包目录。

        :param instance_id: 候选实例 ID
        :return: 该 ID 是否已被占用
        """
        if registry.plugin_class(instance_id) is not None:
            return True
        if instances.get(instance_id) is not None:
            return True
        if instances.get_host(instance_id) is not None:
            return True
        installed = environment.storage().read(
            SystemConfigKey.UserInstalledPlugins
        ) or []
        if instance_id in installed:
            return True
        return (environment.plugins_root / instance_id.lower()).is_dir()

    clone = PluginCloneService(
        plugin_class=registry.plugin_class,
        instance_id_taken=instance_id_taken,
        get_instance=instances.get,
        source_plugin_id=source_plugin_id,
        save_instance=instances.save,
        delete_instance=instances.delete,
        disable_instance=instances.disable,
        read_config=configs.read,
        save_config=lambda plugin_id, config: configs.write(
            plugin_id,
            config,
            force=True,
        ),
        delete_config=lambda plugin_id: configs.delete(plugin_id, force=True),
        reload_plugin=host.reload_plugin,
        remove_plugin=host.remove_plugin,
        log=environment.logger,
    )
    version_inventory = PluginVersionInventory(
        plugins_root=environment.plugins_root,
        # 这里刻意用在册判据而不是类注册表：某插件的全部实例都被停用后重启，注册表里
        # 就没有它的类了，但它装着、实例行也都在，版本总览必须仍然查得出来、切得回去
        plugin_exists=plugin_registered,
        get_instance=instances.get,
        instances_for_source=instances.for_source,
        get_host_instance=instances.get_host,
        running=lambda: registry.running,
        display_name=lambda instance_id: getattr(
            registry.plugin_class(instance_id), "plugin_name", None
        ),
    )
    version_binding = PluginVersionBinding(
        inventory=version_inventory,
        save_instance=instances.save,
        save_host_instance=instances.save_host,
        start=lambda instance_id, version: lifecycle.start(instance_id, version=version),
        stop=lambda plugin_id: _stop_plugin_for_version_binding(lifecycle, plugin_id),
        log=environment.logger,
        refresh_registrations=environment.refresh_registrations,
        pending_installation=_plugin_package_write_probe(host),
    )
    log_level = PluginLogLevelControl(
        plugin_exists=plugin_registered,
        get_instance=instances.get,
        instances_for_source=instances.for_source,
        read_log_level=configs.read_log_level,
        write_log_level=configs.write_log_level,
    )
    default_target = PluginDefaultTargetControl(
        plugin_exists=plugin_registered,
        get_instance=instances.get,
        instances_for_source=instances.for_source,
        get_host_instance=instances.get_host,
        save_host_instance=instances.save_host,
        running=lambda: registry.running,
        set_default_target=environment.set_default_target,
        clear_default_target=environment.clear_default_target,
    )
    projection = PluginProjection(
        registry.running,
        environment.logger,
        environment.remote_entry,
    )
    return PluginRuntime(
        registry=registry,
        instances=instances,
        configs=configs,
        access=access,
        catalog=catalog,
        paths=paths,
        local_sync=local_sync,
        monitor=PluginMonitorController(
            runner=host._run_file_watcher,
            log=environment.logger,
        ),
        admission=PluginMutationAdmission(),
        dependencies=dependencies,
        loader=loader,
        tools=tools,
        lifecycle=lifecycle,
        metadata=metadata,
        sync=sync,
        clone=clone,
        version_inventory=version_inventory,
        version_binding=version_binding,
        log_level=log_level,
        default_target=default_target,
        projection=projection,
        classification=classification,
        recent_local_sync=recent_local_sync,
        system=environment.system,
    )
