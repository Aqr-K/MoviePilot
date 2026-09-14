"""插件 Python 依赖聚合和安装适配器。"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, distribution, distributions
from pathlib import Path
from typing import Any, Optional, Protocol
from urllib.parse import urlsplit

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from app.adapters.system.plugin.health import PluginRuntimeHealth
from app.adapters.system.plugin.manifest import (
    PluginDependencyManifestError,
    load_dependency_manifest,
)
from app.runtime.log import logger
from app.runtime.settings import get_runtime_setting


@dataclass
class _RequirementGroup:
    """聚合同一包和安装来源的 extras 与版本约束。"""

    name: str  # PEP 503 规范化后的包名
    url: Optional[str]  # direct reference 来源；为空表示从索引安装
    extras: set[str] = field(default_factory=set)  # 所有插件要求启用的 extras
    specifiers: set[str] = field(default_factory=set)  # 待求交集的版本约束


@dataclass(frozen=True, slots=True)
class _DependencyInstallRequest:
    """封装一次插件依赖安装所需的清单和本地 wheel 来源。"""

    manifest_paths: list[Path]
    wheels_dirs: list[Path]


# 按插件 ID 给出它本次实际要被扫描的源码目录集合。版本目录布局与实例的版本绑定都属于
# 运行时扩展包，适配器层不得引用，只能由组合根解析好之后注入
PluginDependencyDirectoriesProvider = Callable[[str], Iterable[Path]]


class PluginDependencyPackagePort(Protocol):
    """声明依赖聚合器所需的唯一 Python 包安装边界。"""

    def install_packages_with_fallback(
        self,
        dependency_files: list[Path],
        find_links_dirs: list[Path],
    ) -> tuple[bool, str]:
        """同步安装已经聚合并准入的依赖清单。"""

    async def async_install_packages_with_fallback(
        self,
        dependency_files: list[Path],
        find_links_dirs: list[Path],
    ) -> tuple[bool, str]:
        """异步安装已经聚合并准入的依赖清单。"""


class PluginDependencyInstaller:
    """独立负责插件依赖扫描、约束合并和安装。"""

    def __init__(
        self,
        packages: Optional[PluginDependencyPackagePort] = None,
        *,
        installed_plugins_provider: Optional[Callable[[], list[str]]] = None,
        plugin_dir: Optional[Path] = None,
        plugin_directories_provider: Optional[
            PluginDependencyDirectoriesProvider
        ] = None,
    ) -> None:
        """保存包安装端口、已安装插件读取器和生效源码目录读取器。

        依赖清单与 wheels 随源码一起进了版本目录，不能再假定它们都躺在
        ``app/plugins/<插件ID>`` 这一层：钉在旧版本的实例真正加载的是旧版本目录里的
        代码，按插件根目录或当前版本取清单，装上的依赖与跑着的代码就对不上。
        ``plugin_directories_provider`` 由组合根按实例绑定解析后注入；未注入时退回
        自行发现，见 :meth:`_discover_plugin_directories`。
        """
        if packages is None:
            packages = PluginRuntimeHealth()
        self._packages = packages
        self._installed_plugins_provider = installed_plugins_provider or (lambda: [])
        self._plugin_dir = plugin_dir or (
            Path(get_runtime_setting('ROOT_PATH')) / "app" / "plugins"
        )
        self._plugin_directories_provider = (
            plugin_directories_provider or self._discover_plugin_directories
        )

    @staticmethod
    def _standardize(name: str) -> str:
        """按 PEP 503 兼容规则标准化依赖包名。"""
        return (name or "").lower().replace("-", "_").replace(".", "_")

    @classmethod
    def _installed_packages(cls) -> dict[str, Version]:
        """读取当前 Python 环境中可解析版本的已安装包。"""
        installed: dict[str, Version] = {}
        try:
            for distribution in distributions():
                name = distribution.metadata.get("Name")
                version = distribution.metadata.get("Version") or getattr(
                    distribution,
                    "version",
                    None,
                )
                if not name or not version:
                    continue
                package_name = cls._standardize(name)
                try:
                    parsed = Version(version)
                except InvalidVersion:
                    logger.debug(
                        f"无法解析已安装包 '{package_name}' 的版本：{version}"
                    )
                    continue
                if package_name not in installed or parsed > installed[package_name]:
                    installed[package_name] = parsed
        except Exception as err:
            logger.error(f"获取已安装的包时发生错误：{err}")
        return installed

    @classmethod
    def _installed_distribution(cls, package_name: str) -> Any | None:
        """读取一个包的元数据，用于校验 extras 和 direct URL 来源。"""
        try:
            return distribution(package_name)
        except PackageNotFoundError:
            return None

    def _requirement_satisfied(
        self,
        requirement: Requirement,
        installed: dict[str, Version],
        *,
        seen: Optional[set[tuple[str, tuple[str, ...], Optional[str]]]] = None,
    ) -> bool:
        """同时校验版本、extras 及 direct URL，不把同名包误认为同一制品。"""
        package_name = self._standardize(requirement.name)
        installed_version = installed.get(package_name)
        try:
            if installed_version is None or not SpecifierSet(
                requirement.specifier
            ).contains(installed_version, prereleases=True):
                return False
        except InvalidSpecifier as err:
            logger.error(f"依赖 {package_name} 约束无效：{err}")
            return False

        installed_distribution = self._installed_distribution(package_name)
        if installed_distribution is None:
            return False if requirement.extras or requirement.url else True

        if requirement.url and not self._direct_url_matches(
            installed_distribution, requirement.url
        ):
            return False

        requested_extras = {
            self._standardize_extra(extra) for extra in requirement.extras
        }
        if requested_extras:
            provided_extras = {
                self._standardize_extra(extra)
                for extra in installed_distribution.metadata.get_all(
                    "Provides-Extra"
                )
                or []
            }
            if not requested_extras.issubset(provided_extras):
                return False

        marker_key = (package_name, tuple(sorted(requested_extras)), requirement.url)
        if seen is None:
            seen = set()
        if marker_key in seen:
            return True
        seen.add(marker_key)

        for raw_dependency in installed_distribution.metadata.get_all(
            "Requires-Dist"
        ) or []:
            try:
                extra_dependency = Requirement(raw_dependency)
            except Exception as err:
                logger.debug(
                    f"无法解析已安装包 {package_name} 的依赖项 '{raw_dependency}'：{err}"
                )
                continue
            if not self._marker_matches_for_extras(
                extra_dependency, requested_extras
            ):
                continue
            if not self._requirement_satisfied(
                extra_dependency, installed, seen=seen
            ):
                return False
        return True

    @classmethod
    def _marker_matches_for_extras(
        cls, requirement: Requirement, extras: set[str]
    ) -> bool:
        """判断已安装发行版声明的可选依赖是否属于当前请求的 extra。"""
        if requirement.marker is None:
            return True
        environment = default_environment()
        if "extra" in str(requirement.marker):
            return any(
                requirement.marker.evaluate({**environment, "extra": extra})
                for extra in extras
            )
        return bool(requirement.marker.evaluate(environment))

    @staticmethod
    def _standardize_extra(name: str) -> str:
        """按 PEP 685 兼容规则标准化 extra 名称。"""
        return (name or "").lower().replace("-", "_").replace(".", "_")

    @staticmethod
    def _direct_url_matches(installed_distribution: Any, required_url: str) -> bool:
        """校验安装发行版记录的 PEP 610 URL 与清单来源一致。"""
        try:
            payload = installed_distribution.read_text("direct_url.json")
            if not payload:
                return False
            direct_url = json.loads(payload).get("url")
            if not isinstance(direct_url, str):
                return False
            return PluginDependencyInstaller._canonical_direct_url(
                required_url
            ) == PluginDependencyInstaller._canonical_direct_url(direct_url)
        except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
            return False

    @staticmethod
    def _canonical_direct_url(value: str) -> tuple[str, str, str, str, str]:
        """规范化来源 URL，同时保留 fragment 中可能存在的校验信息。"""
        parsed = urlsplit(value)
        netloc = parsed.netloc.rsplit("@", 1)[-1].lower()
        return (
            parsed.scheme.lower(),
            netloc,
            parsed.path.rstrip("/"),
            parsed.query,
            parsed.fragment,
        )

    @classmethod
    def _merge(cls, dependencies: list[Requirement]) -> list[Requirement]:
        """按包和安装来源合并 extras 与约束，保留完整安装目标。"""
        groups: dict[tuple[str, Optional[str]], _RequirementGroup] = {}
        for requirement in dependencies:
            package_name = cls._standardize(requirement.name)
            key = (package_name, requirement.url)
            group = groups.setdefault(
                key,
                _RequirementGroup(name=package_name, url=requirement.url),
            )
            group.extras.update(requirement.extras)
            group.specifiers.add(str(requirement.specifier))

        merged: list[Requirement] = []
        for group in groups.values():
            spec_set = SpecifierSet()
            for specifier in group.specifiers:
                if not specifier:
                    continue
                try:
                    spec_set &= SpecifierSet(specifier)
                except InvalidSpecifier as err:
                    logger.error(f"发生版本约束冲突：{err}")
            target = group.name
            if group.extras:
                target += f"[{','.join(sorted(group.extras))}]"
            if group.url:
                target += f" @ {group.url}"
            elif spec_set:
                target += str(spec_set)
            merged.append(Requirement(target))
        return merged

    def _discover_plugin_directories(self, plugin_id: str) -> list[Path]:
        """未注入解析端口时自行发现一个插件承载依赖清单的源码目录。

        判据是「这里有没有一份可加载的源码」，而不是目录名像不像版本号：版本目录的
        命名规则属于版本目录布局的所有者，在适配器里再抄一份迟早与它分叉，而分叉的
        后果是依赖静默漏装。插件根目录自带 ``__init__.py`` 即存量平铺布局，只扫根
        目录，与本层引入前逐字一致，插件自带的子包也不会被误当成另一份载荷；根目录
        没有主模块时才向下一层找带主模块的目录，即版本化布局的各个版本目录。

        兜底路径不知道谁绑定了哪一版，因此把全部已装版本一并交出：多扫一个版本最多
        多装几个用不上的包，漏扫一个版本则是那个实例直接起不来。

        :param plugin_id: 插件ID
        :return: 源码目录列表；插件根目录不存在时为空
        """
        plugin_root = self._plugin_dir / plugin_id.lower()
        if not plugin_root.is_dir():
            return []
        if (plugin_root / "__init__.py").is_file():
            return [plugin_root]
        try:
            entries = sorted(plugin_root.iterdir())
        except OSError:
            return [plugin_root]
        version_dirs = [
            entry
            for entry in entries
            if entry.is_dir() and (entry / "__init__.py").is_file()
        ]
        return version_dirs or [plugin_root]

    def _plugin_directories(self, plugin_id: str) -> list[Path]:
        """读取并规范化一个插件本次实际要扫描的源码目录。"""
        try:
            candidates = self._plugin_directories_provider(plugin_id)
        except OSError:
            return []
        directories: list[Path] = []
        seen: set[Path] = set()
        for candidate in candidates or ():
            path = Path(candidate)
            if not path.is_dir():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            directories.append(path)
        return directories

    def _plugin_manifests(self) -> list[Any]:
        """返回已安装插件实际生效的源码目录中的依赖清单。"""
        manifests = []
        installed_plugins = sorted(
            self._installed_plugins_provider() or [],
            key=lambda plugin_id: plugin_id.lower(),
        )
        for plugin_id in installed_plugins:
            plugin_dirs = self._plugin_directories(plugin_id)
            if not plugin_dirs:
                logger.debug(f"忽略插件 {plugin_id} 的依赖：没有可用的源码目录")
                continue
            for plugin_dir in plugin_dirs:
                manifest = load_dependency_manifest(plugin_dir)
                if manifest is None:
                    continue
                manifests.append(manifest)
        return manifests

    def _plugin_dependencies(self) -> list[Requirement]:
        """扫描已安装插件的生效依赖清单并合并版本约束。"""
        dependencies: list[Requirement] = []
        for manifest in self._plugin_manifests():
            for requirement in manifest.dependencies:
                if requirement.marker and not requirement.marker.evaluate():
                    continue
                dependencies.append(requirement)
        return self._merge(dependencies)

    def find_missing(self) -> list[str]:
        """返回当前插件集合缺失或不满足约束的依赖项。"""
        try:
            required = self._plugin_dependencies()
            installed = self._installed_packages()
            missing = []
            for requirement in required:
                if not self._requirement_satisfied(requirement, installed):
                    missing.append(str(requirement))
            return missing
        except PluginDependencyManifestError:
            raise
        except Exception as err:
            logger.error(f"收集所有需要安装或更新的依赖项时发生错误：{err}")
            return []

    def classify_plugins(self) -> tuple[list[str], list[str], list[str]]:
        """按源码和依赖状态划分已安装插件。"""
        ready: list[str] = []
        missing_dependencies: list[str] = []
        missing_source: list[str] = []
        installed_packages = self._installed_packages()

        for plugin_id in self._installed_plugins_provider() or []:
            plugin_dirs = self._plugin_directories(plugin_id)
            if not plugin_dirs:
                missing_source.append(plugin_id)
                continue
            try:
                requirements = [
                    requirement
                    for plugin_dir in plugin_dirs
                    for requirement in self._directory_requirements(plugin_dir)
                ]
            except PluginDependencyManifestError as error:
                logger.error(f"插件 {plugin_id} 依赖清单无效：{error}")
                missing_dependencies.append(plugin_id)
                continue
            if all(
                self._requirement_satisfied(requirement, installed_packages)
                for requirement in requirements
            ):
                ready.append(plugin_id)
            else:
                missing_dependencies.append(plugin_id)

        return ready, missing_dependencies, missing_source

    def installed_packages_snapshot(self) -> dict[str, Version]:
        """给出一份已安装包快照，供同一轮逐目录分类复用。

        读一次要遍历整个环境的发行版元数据，开销接近百毫秒级；逐个实例各读一次会
        让一次启动分类多花好几秒，而同一轮分类里 Python 环境本来就不会变。
        """
        return self._installed_packages()

    def classify_plugin_directory(
        self,
        plugin_directory: Path,
        *,
        installed_packages: Optional[dict[str, Version]] = None,
    ) -> tuple[bool, bool]:
        """按一个确定的源码目录返回 ``(源码存在, 依赖就绪)``。

        :meth:`classify_plugins` 只能给出「这个插件的全部生效版本合起来怎么样」，
        而钉在不同版本的实例各自加载的是不同的源码，合并结论会把「旧版本本体就绪」
        与「新版本分身缺依赖」压成同一个状态，随后被逐个 ``start()`` 的实例因此拿到
        别人的结论。这个窄端口只消费调用方已经解析好的目录，不读实例表也不碰版本
        布局，把「谁用哪个目录」留在运行时层回答。

        :param plugin_directory: 已解析出的源码目录
        :param installed_packages: 已安装包快照，供批量分类复用，缺省时现场读取
        :return: 源码目录是否存在，以及该目录声明的依赖是否全部满足
        """
        if not plugin_directory.is_dir():
            return False, False
        try:
            requirements = self._directory_requirements(plugin_directory)
        except PluginDependencyManifestError as error:
            logger.error(f"插件依赖清单无效：{plugin_directory} - {error}")
            return True, False
        installed = (
            self._installed_packages()
            if installed_packages is None
            else installed_packages
        )
        return True, all(
            self._requirement_satisfied(requirement, installed)
            for requirement in requirements
        )

    @staticmethod
    def _directory_requirements(plugin_dir: Path) -> list[Requirement]:
        """读取一个源码目录中当前环境真正生效的依赖项。"""
        manifest = load_dependency_manifest(plugin_dir)
        if manifest is None:
            return []
        return [
            requirement
            for requirement in manifest.dependencies
            if not requirement.marker or requirement.marker.evaluate()
        ]

    def _wheels_dirs(self) -> list[Path]:
        """收集实际生效的源码目录里附带的本地 wheels 目录。

        按安装清单顺序遍历而不是先收进集合：这个列表会原样变成 ``--find-links``
        参数，集合的迭代序每个进程都不一样，同一台机器两次安装打出的命令行与日志
        因此对不上，失败复现只能靠猜。去重仍由 ``dict.fromkeys`` 承担。
        """
        result = []
        for plugin_id in self._installed_plugins_provider() or []:
            for plugin_dir in self._plugin_directories(plugin_id):
                wheels_dir = plugin_dir / "wheels"
                if wheels_dir.is_dir():
                    result.append(wheels_dir)
        return list(dict.fromkeys(result))

    def _prepare_install_request(
        self, dependencies: list[str]
    ) -> tuple[Optional[_DependencyInstallRequest], Optional[tuple[bool, str]]]:
        """统一校验依赖安装请求，并在进入包 I/O 前构造规范输入。"""
        if not dependencies:
            return None, (False, "没有传入需要安装的依赖项")
        try:
            manifest_paths = [manifest.path for manifest in self._plugin_manifests()]
            if not manifest_paths:
                return None, (False, "没有找到已安装插件的依赖清单")
            return (
                _DependencyInstallRequest(
                    manifest_paths=manifest_paths,
                    wheels_dirs=self._wheels_dirs(),
                ),
                None,
            )
        except Exception as error:  # noqa: BLE001 - 统一映射为公开安装结果
            return None, self._dependency_install_failure(error)

    @staticmethod
    def _dependency_install_failure(error: Exception) -> tuple[bool, str]:
        """统一记录同步与异步包安装异常，并保留既有错误文本合同。"""
        message = f"安装依赖项时发生错误：{error}"
        logger.error(message)
        return False, message

    def install(self, dependencies: list[str]) -> tuple[bool, str]:
        """把已安装插件的原始清单交给一次统一包安装。"""
        request, error_result = self._prepare_install_request(dependencies)
        if error_result is not None:
            return error_result
        assert request is not None
        try:
            return self._packages.install_packages_with_fallback(
                request.manifest_paths,
                request.wheels_dirs,
            )
        except Exception as error:  # noqa: BLE001 - 统一映射为公开安装结果
            return self._dependency_install_failure(error)

    async def async_find_missing(self) -> list[str]:
        """在线程池中扫描缺失依赖，避免阻塞事件循环。"""
        return await asyncio.to_thread(self.find_missing)

    async def async_install(self, dependencies: list[str]) -> tuple[bool, str]:
        """异步安装依赖，使用可取消的包安装子进程。"""
        request, error_result = self._prepare_install_request(dependencies)
        if error_result is not None:
            return error_result
        assert request is not None
        try:
            return await self._packages.async_install_packages_with_fallback(
                request.manifest_paths,
                request.wheels_dirs,
            )
        except Exception as error:  # noqa: BLE001 - 统一映射为公开安装结果
            return self._dependency_install_failure(error)
