"""插件依赖按实例绑定的版本目录扫描与分类的合同测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock

import pytest
from packaging.requirements import Requirement

from app.adapters.system.plugin.dependency import PluginDependencyInstaller
from app.runtime.extensions.plugin.dependency import PluginDependencyService
from app.runtime.extensions.plugin.version import (
    plugin_version_dir_name,
    register_plugin_version,
    resolve_instance_version_dir,
)
from app.schemas.plugin import PluginInstance
from app.startup.composition.plugin import _bound_plugin_directories

PLUGIN_ID = "DemoPlugin"


def _versioned_plugin(
    plugins_root: Path,
    requirements: dict[str, str],
    *,
    current: str,
    plugin_id: str = PLUGIN_ID,
) -> Path:
    """按版本目录布局写出一个插件的多个版本，每版各带自己的依赖清单。

    :param plugins_root: 插件安装根目录（``app/plugins``）
    :param requirements: 版本号到该版本 requirements.txt 内容的映射，内容为空则不写清单
    :param current: 元信息里登记的当前版本号
    :param plugin_id: 插件ID
    :return: 插件源码根目录
    """
    plugin_root = plugins_root / plugin_id.lower()
    for version, content in requirements.items():
        version_dir = plugin_root / plugin_version_dir_name(version)
        version_dir.mkdir(parents=True)
        (version_dir / "__init__.py").write_text(
            f'class DemoPlugin:\n    plugin_version = "{version}"\n',
            encoding="utf-8",
        )
        if content:
            (version_dir / "requirements.txt").write_text(content, encoding="utf-8")
        register_plugin_version(plugin_root, version, "market")
    register_plugin_version(plugin_root, current, "market")
    return plugin_root


def _installer(
    plugins_root: Path,
    directories: list[Path],
    *,
    packages: Optional[Mock] = None,
) -> PluginDependencyInstaller:
    """构造一个按给定目录集合扫描依赖的安装器。"""
    return PluginDependencyInstaller(
        packages or Mock(),
        installed_plugins_provider=lambda: [PLUGIN_ID],
        plugin_dir=plugins_root,
        plugin_directories_provider=lambda _plugin_id: directories,
    )


def _missing_names(installer: PluginDependencyInstaller) -> list[str]:
    """返回缺失依赖的包名，屏蔽约束文本差异。"""
    return sorted(Requirement(item).name for item in installer.find_missing())


def _silent_log() -> SimpleNamespace:
    """给出一个吞掉全部输出的日志端口。"""
    return SimpleNamespace(
        debug=lambda *_args, **_kwargs: None,
        info=lambda *_args, **_kwargs: None,
        warning=lambda *_args, **_kwargs: None,
        error=lambda *_args, **_kwargs: None,
    )


# --------------------------------------------------------------------------- #
# 适配器：依赖清单与 wheels 必须来自实例实际加载的那个版本目录
# --------------------------------------------------------------------------- #


def test_dependency_scan_reads_the_manifest_of_the_pinned_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """钉在旧版本的实例必须按旧版本目录的清单装依赖，而不是当前版本的清单。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": "new-pkg>=1\n"},
        current="2.0.0",
    )
    pinned = PluginInstance(
        instance_id=PLUGIN_ID,
        source_plugin_id=PLUGIN_ID,
        pinned_version="1.0.0",
    )
    installer = _installer(
        plugins_root,
        [resolve_instance_version_dir(plugin_root, pinned)],
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert _missing_names(installer) == ["old_pkg"]


def test_dependency_scan_follows_the_current_version_without_a_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """跟随当前版本的实例按当前版本目录的清单装依赖。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": "new-pkg>=1\n"},
        current="2.0.0",
    )
    installer = _installer(
        plugins_root,
        [resolve_instance_version_dir(plugin_root, None)],
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert _missing_names(installer) == ["new_pkg"]


def test_dependency_scan_aggregates_every_bound_version_of_one_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同一插件的两个实例钉在不同版本时，两份清单都要被扫到。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": "new-pkg>=1\n"},
        current="2.0.0",
    )
    pinned = PluginInstance(
        instance_id=f"{PLUGIN_ID}Work",
        source_plugin_id=PLUGIN_ID,
        pinned_version="1.0.0",
    )
    installer = _installer(
        plugins_root,
        [
            resolve_instance_version_dir(plugin_root, None),
            resolve_instance_version_dir(plugin_root, pinned),
        ],
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert _missing_names(installer) == ["new_pkg", "old_pkg"]


def test_install_passes_the_bound_version_manifests_and_wheels(tmp_path: Path) -> None:
    """安装交给包管理器的清单与 wheels 目录都取自绑定的版本目录。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": "new-pkg>=1\n"},
        current="2.0.0",
    )
    (plugin_root / plugin_version_dir_name("1.0.0") / "wheels").mkdir()
    (plugin_root / plugin_version_dir_name("2.0.0") / "wheels").mkdir()
    packages = Mock()
    packages.install_packages_with_fallback.return_value = (True, "")
    pinned = PluginInstance(
        instance_id=PLUGIN_ID,
        source_plugin_id=PLUGIN_ID,
        pinned_version="1.0.0",
    )
    installer = _installer(
        plugins_root,
        [resolve_instance_version_dir(plugin_root, pinned)],
        packages=packages,
    )

    assert installer.install(["old-pkg>=1"]) == (True, "")
    manifest_paths, wheels_dirs = packages.install_packages_with_fallback.call_args[0]
    assert [path.parent.name for path in manifest_paths] == ["v1_0_0"]
    assert [path.parent.name for path in wheels_dirs] == ["v1_0_0"]


def test_default_discovery_scans_version_directories_when_no_port_is_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """未注入版本解析端口的兜底路径也要看到版本目录，不能静默漏装依赖。"""
    plugins_root = tmp_path / "plugins"
    _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": "new-pkg>=1\n"},
        current="2.0.0",
    )
    installer = PluginDependencyInstaller(
        Mock(),
        installed_plugins_provider=lambda: [PLUGIN_ID],
        plugin_dir=plugins_root,
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert _missing_names(installer) == ["new_pkg", "old_pkg"]


def test_default_discovery_keeps_flat_layout_scanning_the_plugin_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """存量平铺布局下兜底路径只扫插件根目录，插件自带的子包不得被当成版本目录。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = plugins_root / PLUGIN_ID.lower()
    (plugin_root / "vendor").mkdir(parents=True)
    (plugin_root / "__init__.py").write_text("", encoding="utf-8")
    (plugin_root / "requirements.txt").write_text("flat-pkg>=1\n", encoding="utf-8")
    (plugin_root / "vendor" / "__init__.py").write_text("", encoding="utf-8")
    (plugin_root / "vendor" / "requirements.txt").write_text(
        "vendored-pkg>=1\n", encoding="utf-8"
    )
    installer = PluginDependencyInstaller(
        Mock(),
        installed_plugins_provider=lambda: [PLUGIN_ID],
        plugin_dir=plugins_root,
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert _missing_names(installer) == ["flat_pkg"]


def test_classify_plugin_directory_answers_source_and_dependency_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """窄端口按单个目录给出源码是否存在与依赖是否就绪。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": ""},
        current="2.0.0",
    )
    installer = _installer(plugins_root, [])
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})

    assert installer.classify_plugin_directory(
        plugin_root / plugin_version_dir_name("2.0.0")
    ) == (True, True)
    assert installer.classify_plugin_directory(
        plugin_root / plugin_version_dir_name("1.0.0")
    ) == (True, False)
    assert installer.classify_plugin_directory(plugin_root / "v9_9_9") == (False, False)


# --------------------------------------------------------------------------- #
# 运行时：按版本目录分类之前必须先过装载判据
# --------------------------------------------------------------------------- #


def _bound_service(
    *,
    classify_plugins,
    classify_plugin_directory,
    instances: dict[str, PluginInstance],
    loadable_hosts: set[str],
    instance_directory,
    host_instance=lambda _plugin_id: None,
) -> PluginDependencyService:
    """构造一个已装配版本目录解析端口的依赖分类服务。"""
    return PluginDependencyService(
        system=lambda: SimpleNamespace(
            dependency=SimpleNamespace(
                classify_plugins=classify_plugins,
                classify_plugin_directory=(
                    lambda directory, installed_packages=None: (
                        classify_plugin_directory(directory)
                    )
                ),
                installed_packages_snapshot=lambda: {},
            )
        ),
        instances=lambda: instances,
        loadable_hosts=lambda: loadable_hosts,
        log=_silent_log(),
        instance_directory=instance_directory,
        host_instance=host_instance,
    )


def test_bound_classification_still_drops_hosts_that_are_not_loadable() -> None:
    """按版本目录分类之后，停用的本体仍然不得出现在任何一个桶里。

    分类结果会被逐个 ``start()``；安装清单只回答「包在不在磁盘上」，回答不了「这份
    配置该不该跑」。按版本目录细分的是「用哪一份源码」，替代不了启用位这道装载判据，
    少了它停用的插件会在开机与配置热重载时被重新拉起来，``is_enabled`` 形同虚设。
    """
    service = _bound_service(
        classify_plugins=lambda: (["PluginA", "PluginB"], ["PluginC"], ["PluginD"]),
        classify_plugin_directory=lambda _directory: (True, True),
        instances={},
        loadable_hosts={"PluginA"},
        instance_directory=lambda _source_plugin_id, _instance: Path("/plugins/any"),
    )

    classification = service.classify_plugins()

    assert classification.ready == ("PluginA",)
    assert "PluginB" not in classification.ready
    assert classification.missing_dependencies == ()
    assert classification.missing_source == ()


def test_bound_classification_drops_instances_whose_host_is_not_loadable() -> None:
    """本体被装载判据剔除时，它名下的分身同样不进入 ready 桶。"""
    service = _bound_service(
        classify_plugins=lambda: (["PluginA", "PluginB"], [], []),
        classify_plugin_directory=lambda _directory: (True, True),
        instances={
            "PluginBx2": PluginInstance(
                instance_id="PluginBx2", source_plugin_id="PluginB"
            )
        },
        loadable_hosts={"PluginA"},
        instance_directory=lambda _source_plugin_id, _instance: Path("/plugins/any"),
    )

    classification = service.classify_plugins()

    assert classification.ready == ("PluginA",)
    assert classification.missing_source == ("PluginBx2",)


def test_bound_classification_splits_instances_by_their_own_version_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """本体跟随当前版本、分身钉在缺依赖的旧版本时，两者各自得到自己的结论。

    合并全部生效版本得到的粗结论是「这个插件缺依赖」，逐实例复核后必须细分成
    本体就绪、分身等依赖，而不是让本体陪着分身一起停在等依赖。
    """
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": ""},
        current="2.0.0",
    )
    installer = _installer(
        plugins_root,
        [
            plugin_root / plugin_version_dir_name("1.0.0"),
            plugin_root / plugin_version_dir_name("2.0.0"),
        ],
    )
    monkeypatch.setattr(installer, "_installed_packages", lambda: {})
    clone = PluginInstance(
        instance_id=f"{PLUGIN_ID}Work",
        source_plugin_id=PLUGIN_ID,
        pinned_version="1.0.0",
    )
    service = PluginDependencyService(
        system=lambda: SimpleNamespace(dependency=installer),
        instances=lambda: {clone.instance_id: clone},
        loadable_hosts=lambda: {PLUGIN_ID},
        log=_silent_log(),
        instance_directory=lambda _source_plugin_id, instance: (
            resolve_instance_version_dir(plugin_root, instance)
        ),
    )

    classification = service.classify_plugins()

    assert classification.ready == (PLUGIN_ID,)
    assert classification.missing_dependencies == (f"{PLUGIN_ID}Work",)
    assert classification.missing_source == ()


def test_bound_classification_reads_the_installed_packages_once_per_round(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """逐实例复核共用一份已安装包快照，遍历整个环境的元数据每轮只做一次。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "old-pkg>=1\n", "2.0.0": ""},
        current="2.0.0",
    )
    installer = _installer(
        plugins_root,
        [
            plugin_root / plugin_version_dir_name("1.0.0"),
            plugin_root / plugin_version_dir_name("2.0.0"),
        ],
    )
    scans = 0

    def _count_scans() -> dict:
        """统计整轮分类里扫描已安装包的次数。"""
        nonlocal scans
        scans += 1
        return {}

    monkeypatch.setattr(installer, "_installed_packages", _count_scans)
    clones = {
        f"{PLUGIN_ID}Work{index}": PluginInstance(
            instance_id=f"{PLUGIN_ID}Work{index}",
            source_plugin_id=PLUGIN_ID,
            pinned_version="1.0.0",
        )
        for index in range(3)
    }
    service = PluginDependencyService(
        system=lambda: SimpleNamespace(dependency=installer),
        instances=lambda: clones,
        loadable_hosts=lambda: {PLUGIN_ID},
        log=_silent_log(),
        instance_directory=lambda _source_plugin_id, instance: (
            resolve_instance_version_dir(plugin_root, instance)
        ),
    )

    service.classify_plugins()

    # 一次来自适配器的粗分类，一次来自整轮共用的快照
    assert scans == 2


def test_bound_classification_reports_missing_source_when_the_port_fails() -> None:
    """版本目录解析失败时按缺源码处理，不把一个来路不明的实例照样拉起来。"""

    def _explode(_source_plugin_id: str, _instance) -> Path:
        raise RuntimeError("实例表暂时不可读")

    service = _bound_service(
        classify_plugins=lambda: (["PluginA"], [], []),
        classify_plugin_directory=lambda _directory: (True, True),
        instances={},
        loadable_hosts={"PluginA"},
        instance_directory=_explode,
    )

    classification = service.classify_plugins()

    assert classification.ready == ()
    assert classification.missing_source == ("PluginA",)


# --------------------------------------------------------------------------- #
# 组合根：按实例绑定收敛出要扫描的版本目录
# --------------------------------------------------------------------------- #


def _bind(monkeypatch: pytest.MonkeyPatch, host, clones) -> None:
    """把组合根看到的版本绑定替换为给定的本体与分身。"""
    manager = SimpleNamespace(
        get_plugin_version_binding=lambda _plugin_id: host,
        get_plugin_source_instances=lambda _plugin_id: list(clones),
    )
    monkeypatch.setattr(
        "app.application.plugin.runtime.get_existing_plugin_manager",
        lambda: manager,
    )


def test_bound_directories_cover_the_host_and_every_clone_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """本体钉旧版、分身跟随当前版本时，两个版本目录都要被交给依赖扫描。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "", "2.0.0": ""},
        current="2.0.0",
    )
    _bind(
        monkeypatch,
        PluginInstance(
            instance_id=PLUGIN_ID,
            source_plugin_id=PLUGIN_ID,
            pinned_version="1.0.0",
        ),
        [
            PluginInstance(
                instance_id=f"{PLUGIN_ID}Work",
                source_plugin_id=PLUGIN_ID,
            )
        ],
    )

    directories = _bound_plugin_directories(PLUGIN_ID, plugin_root)

    assert [directory.name for directory in directories] == ["v1_0_0", "v2_0_0"]


def test_bound_directories_fall_back_to_every_installed_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """绑定查询不可用时回落到磁盘上全部版本目录，宁可多扫也不漏装依赖。"""
    plugins_root = tmp_path / "plugins"
    plugin_root = _versioned_plugin(
        plugins_root,
        {"1.0.0": "", "2.0.0": ""},
        current="2.0.0",
    )

    def _explode() -> None:
        raise RuntimeError("插件运行时尚未物化")

    monkeypatch.setattr(
        "app.application.plugin.runtime.get_existing_plugin_manager",
        _explode,
    )

    directories = _bound_plugin_directories(PLUGIN_ID, plugin_root)

    assert [directory.name for directory in directories] == ["v1_0_0", "v2_0_0"]
