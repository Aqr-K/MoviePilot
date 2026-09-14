"""插件依赖检查与安装运行时服务。"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, cast

from app.runtime.extensions.plugin.registry import PluginRegistry
from app.runtime.extensions.plugin.system import PluginSystemServices
from app.schemas.plugin import PluginInstance, PluginRuntimeStatus

# 按「源插件 ID + 该实例的绑定」解析出这个实例实际会加载的源码目录
PluginInstanceDirectoryProvider = Callable[
    [str, Optional[PluginInstance]],
    Optional[Path],
]
# 读取源插件本体自身那一行，本体同样可能被钉在某个版本上
PluginHostInstanceProvider = Callable[[str], Optional[PluginInstance]]


@dataclass(frozen=True)
class PluginDependencyInstallResult:
    """记录插件依赖检查结果，区分无缺失、安装成功和安装失败。"""

    missing: list[str]
    success: bool


@dataclass(frozen=True)
class PluginDependencyClassification:
    """按当前源码和 Python 环境划分已安装插件。"""

    ready: tuple[str, ...]
    missing_dependencies: tuple[str, ...]
    missing_source: tuple[str, ...]


class PluginDependencyService:
    """执行缺失插件依赖的发现和安装，不参与插件生命周期。"""

    def __init__(
        self,
        *,
        system: Callable[[], PluginSystemServices],
        instances: Optional[Callable[[], dict[str, PluginInstance]]] = None,
        loadable_hosts: Optional[Callable[[], set[str]]] = None,
        registry: Optional[PluginRegistry] = None,
        log: Any,
        instance_directory: Optional[PluginInstanceDirectoryProvider] = None,
        host_instance: Optional[PluginHostInstanceProvider] = None,
    ) -> None:
        """保存插件系统、应装载实例、应装载本体、版本目录解析和运行状态端口。

        ``loadable_hosts`` 回答「这份配置该不该跑」，``instance_directory`` 回答
        「该跑的那个实例用哪一份源码」。两者是彼此独立的判据，缺一不可：只按版本
        目录分类会让停用的插件重新被拉起来，只按启用位过滤则会让钉在不同版本的实例
        共用一个依赖结论。
        """
        self._system = system
        self._instances = instances or (lambda: {})
        self._loadable_hosts = loadable_hosts
        self._registry = registry
        self._logger = log
        self._instance_directory = instance_directory
        self._host_instance = host_instance or (lambda _plugin_id: None)

    def _begin_missing_install(self, missing: list[str]) -> Optional[float]:
        """统一无缺失短路、安装清单日志和耗时起点。"""
        if not missing:
            return None
        self._logger.debug(f"检测到缺失的依赖项: {missing}")
        self._logger.info(f"开始安装缺失的依赖项，共 {len(missing)} 个...")
        return time.time()

    def _complete_missing_install(
        self,
        missing: list[str],
        success: bool,
        started_at: float,
    ) -> PluginDependencyInstallResult:
        """统一安装结果、耗时和成功或失败日志分类。"""
        elapsed = time.time() - started_at
        if success:
            self._logger.info(
                f"已完成 {len(missing)} 个依赖项安装，总耗时：{elapsed:.2f} 秒"
            )
        else:
            self._logger.warning(
                f"存在缺失依赖项安装失败，请尝试手动安装，总耗时：{elapsed:.2f} 秒"
            )
        return PluginDependencyInstallResult(missing=missing, success=success)

    def install_missing_with_status(self) -> PluginDependencyInstallResult:
        """安装缺失依赖并返回安装器的明确结果。"""
        installer = self._system().dependency
        missing = installer.find_missing()
        started_at = self._begin_missing_install(missing)
        if started_at is None:
            return PluginDependencyInstallResult(missing=[], success=True)
        success, _message = installer.install(missing)
        return self._complete_missing_install(missing, success, started_at)

    def install_missing(self) -> list[str]:
        """安装当前环境缺失的插件依赖并保持历史列表返回合同。"""
        return self.install_missing_with_status().missing

    async def async_install_missing_with_status(self) -> PluginDependencyInstallResult:
        """在异步启动链中恢复缺失依赖，确保安装子进程可取消。"""
        installer = self._system().dependency
        missing = await installer.async_find_missing()
        started_at = self._begin_missing_install(missing)
        if started_at is None:
            return PluginDependencyInstallResult(missing=[], success=True)
        success, _message = await installer.async_install(missing)
        return self._complete_missing_install(missing, success, started_at)

    def classify_plugins(self) -> PluginDependencyClassification:
        """分类应当装载的物理插件，并把结论落到应当装载的每一个实例上。

        物理插件那一层按安装清单划分，而安装清单只回答「包在不在磁盘上」；分类结果
        随后会被逐个 ``start()``，因此这里必须先按启用位过滤掉停用的本体，否则停用
        的插件会在开机与配置热重载时被重新拉起来，启用位形同虚设。三个桶一起过滤：
        停用的插件既不该被装载，也不该为它安装缺失依赖。

        过滤之后才轮到版本：装配了版本目录解析端口时，幸存者按各自绑定的版本目录
        逐个复核，钉在不同版本的实例因此各自得到自己那份源码的结论；没装配时沿用
        「本体什么状态、分身就什么状态」的旧映射。
        """
        installer = self._system().dependency
        ready, missing_dependencies, missing_source = installer.classify_plugins()
        loadable = self._loadable_hosts() if self._loadable_hosts is not None else None
        if loadable is not None:
            ready = [plugin_id for plugin_id in ready if plugin_id in loadable]
            missing_dependencies = [
                plugin_id for plugin_id in missing_dependencies if plugin_id in loadable
            ]
            missing_source = [
                plugin_id for plugin_id in missing_source if plugin_id in loadable
            ]
        ready = list(ready)
        missing_dependencies = list(missing_dependencies)
        missing_source = list(missing_source)
        if self._instance_directory is not None:
            return self._classify_bound_instances(
                installer, ready, missing_dependencies, missing_source
            )
        source_ready = set(ready)
        source_pending = set(missing_dependencies)
        for instance in self._instances().values():
            if instance.source_plugin_id in source_ready:
                ready.append(instance.instance_id)
            elif instance.source_plugin_id in source_pending:
                missing_dependencies.append(instance.instance_id)
            else:
                missing_source.append(instance.instance_id)
        return PluginDependencyClassification(
            ready=tuple(ready),
            missing_dependencies=tuple(missing_dependencies),
            missing_source=tuple(missing_source),
        )

    def _classify_bound_instances(
        self,
        installer: Any,
        ready: list[str],
        missing_dependencies: list[str],
        missing_source: list[str],
    ) -> PluginDependencyClassification:
        """对已通过装载判据的本体与分身，按各自绑定的版本目录逐个复核。

        源码整个不在磁盘上的本体直接沿用上一层的结论，不必再解析一次版本目录——
        没有插件根目录就没有任何版本目录可言。分身仍以本体的源码结论为前提：本体
        被启用位剔除或源码缺失时，分身照旧归入缺源码，与未装配版本端口时一致，
        本层只改「用哪一份源码判依赖」，不改「谁有资格被装载」。

        :param installer: 依赖安装器，提供按目录分类的窄端口
        :param ready: 已过装载判据、源码就绪且依赖满足的本体
        :param missing_dependencies: 已过装载判据、源码就绪但缺依赖的本体
        :param missing_source: 已过装载判据但源码不在磁盘上的本体
        :return: 逐实例的分类结果
        """
        source_present = set(ready) | set(missing_dependencies)
        result_ready: list[str] = []
        result_pending: list[str] = []
        result_missing: list[str] = list(missing_source)
        # 整轮共用一份已安装包快照：逐个实例各读一次要遍历整个环境的发行版元数据，
        # 而同一轮分类里 Python 环境不会变
        packages = installer.installed_packages_snapshot()

        def place(identifier: str, verdict: tuple[bool, bool]) -> None:
            """把一次目录复核结果放进对应的桶。"""
            exists, satisfied = verdict
            if not exists:
                result_missing.append(identifier)
            elif satisfied:
                result_ready.append(identifier)
            else:
                result_pending.append(identifier)

        for plugin_id in (*ready, *missing_dependencies):
            place(
                plugin_id,
                self._directory_verdict(
                    installer, plugin_id, self._host_instance(plugin_id), packages
                ),
            )
        for instance in self._instances().values():
            if instance.source_plugin_id not in source_present:
                result_missing.append(instance.instance_id)
                continue
            place(
                instance.instance_id,
                self._directory_verdict(
                    installer, instance.source_plugin_id, instance, packages
                ),
            )
        return PluginDependencyClassification(
            ready=tuple(result_ready),
            missing_dependencies=tuple(result_pending),
            missing_source=tuple(result_missing),
        )

    def _directory_verdict(
        self,
        installer: Any,
        source_plugin_id: str,
        instance: Optional[PluginInstance],
        packages: Any,
    ) -> tuple[bool, bool]:
        """读取一个实例绑定的版本目录的源码与依赖状态。

        解析不出目录时按缺源码处理：判据未知就把实例拦在装载之外，而不是让它带着
        一份来路不明的源码被启动。目录在、只是依赖判不出来时按缺依赖处理，这条路径
        还能被下一轮依赖安装救回来。

        :param installer: 依赖安装器，提供按目录分类的窄端口
        :param source_plugin_id: 提供源码的插件 ID
        :param instance: 该实例的版本绑定；为空表示按插件当前版本解析
        :param packages: 整轮共用的已安装包快照
        :return: 源码目录是否存在，以及该目录声明的依赖是否全部满足
        """
        resolve = self._instance_directory
        if resolve is None:
            return False, False
        try:
            directory = resolve(source_plugin_id, instance)
        except Exception as error:  # noqa: BLE001 - 判据未知必须失败关闭
            self._logger.error(
                f"解析插件 {source_plugin_id} 的实例版本目录失败：{error}"
            )
            return False, False
        if directory is None:
            return False, False
        try:
            return cast(
                tuple[bool, bool],
                installer.classify_plugin_directory(
                    directory, installed_packages=packages
                ),
            )
        except Exception as error:  # noqa: BLE001 - 判据未知必须失败关闭
            self._logger.error(
                f"检查插件 {source_plugin_id} 在 {directory} 的依赖失败：{error}"
            )
            return True, False

    def apply_classification(
        self,
        classification: PluginDependencyClassification,
    ) -> None:
        """把依赖分类写入唯一注册表，已激活插件保持当前状态。"""
        if self._registry is None:
            raise RuntimeError("插件依赖状态注册表尚未装配")
        running_ids = set(self._registry.running_ids())
        for plugin_id in classification.missing_source:
            self._registry.set_runtime_status(
                plugin_id,
                PluginRuntimeStatus.SOURCE_MISSING,
            )
        for plugin_id in classification.missing_dependencies:
            self._registry.set_runtime_status(
                plugin_id,
                PluginRuntimeStatus.DEPENDENCY_PENDING,
            )
        for plugin_id in classification.ready:
            current_status = self._registry.runtime_status(plugin_id)
            if (
                plugin_id in running_ids
                and current_status is not PluginRuntimeStatus.DEPENDENCY_PENDING
            ):
                continue
            self._registry.set_runtime_status(
                plugin_id,
                PluginRuntimeStatus.READY,
            )
