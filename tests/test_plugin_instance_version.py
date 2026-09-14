"""插件实例版本绑定字段、加载期版本解析与生命周期版本穿透测试。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.runtime.extensions.plugin.database import PluginDatabase
from app.runtime.extensions.plugin.lifecycle import PluginLifecycle
from app.runtime.extensions.plugin.loader import PluginLoader
from app.runtime.extensions.plugin.version import (
    plugin_version_dir_name,
    resolve_instance_version_dir,
    write_plugin_versions_manifest,
)
from app.schemas.plugin import PluginInstance


def _logger() -> SimpleNamespace:
    """提供加载器与生命周期测试所需的最小日志端口。"""
    return SimpleNamespace(
        debug=lambda *_args: None,
        info=lambda *_args: None,
        warning=lambda *_args: None,
        error=lambda *_args: None,
    )


def _make_loader(plugins_root: Path, **overrides) -> PluginLoader:
    """构造只需最小日志端口的加载器实例，可覆盖本体版本绑定查询端口。"""
    return PluginLoader(
        plugins_root=plugins_root,
        import_preparer=lambda **_kwargs: None,
        import_scanner=lambda **_kwargs: None,
        log=_logger(),
        **overrides,
    )


def _write_version(
    plugins_root: Path,
    plugin_id: str,
    version: str,
    *,
    marker: str,
) -> Path:
    """写入一个版本目录的最小可加载源码，marker 用于区分哪个版本被加载到。"""
    version_dir = plugins_root / plugin_id / plugin_version_dir_name(version)
    version_dir.mkdir(parents=True)
    (version_dir / "__init__.py").write_text(
        f"class Versioned:\n"
        f"    plugin_name = '版本化插件'\n"
        f"    plugin_version = {version!r}\n"
        f"    marker = {marker!r}\n"
        "    def init_plugin(self, config=None):\n"
        "        pass\n",
        encoding="utf-8",
    )
    return version_dir


def _write_manifest(
    plugin_root: Path, entries: list[tuple[str, str]], current: str | None
) -> None:
    """写入版本元信息文件。"""
    write_plugin_versions_manifest(
        plugin_root,
        [
            {
                "version": version,
                "directory": directory,
                "installed_at": "2026-01-01T00:00:00+00:00",
                "source": "test",
            }
            for version, directory in entries
        ],
        current,
    )


def _two_versions(tmp_path: Path, *, current: str = "2.0.0") -> Path:
    """备好一个装有 1.0.0 与 2.0.0 两个版本目录的插件，并登记当前版本。"""
    _write_version(tmp_path, "versioned", "1.0.0", marker="old")
    _write_version(tmp_path, "versioned", "2.0.0", marker="new")
    _write_manifest(
        tmp_path / "versioned",
        [("1.0.0", "v1_0_0"), ("2.0.0", "v2_0_0")],
        current=current,
    )
    return tmp_path / "versioned"


def _accepts_plugin(candidate: object) -> bool:
    """按宿主最小插件契约筛选候选类。"""
    return hasattr(candidate, "init_plugin") and hasattr(candidate, "plugin_name")


@pytest.fixture(autouse=True)
def _isolate_plugin_modules():
    """回收测试期间手动导入的临时插件模块，避免污染其它用例的模块缓存。"""
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        if name.startswith("app.plugins."):
            sys.modules.pop(name, None)


# 一、实例描述符上的版本绑定字段


def test_plugin_instance_defaults_to_following_the_current_version():
    """新建实例默认不钉版本，即跟随插件当前版本。"""
    instance = PluginInstance(instance_id="DemoPluginWork", source_plugin_id="DemoPlugin")

    assert instance.pinned_version is None


def test_plugin_instance_accepts_a_pinned_version():
    """钉住某个版本时原样保留，不做任何归一或推导。"""
    instance = PluginInstance(
        instance_id="DemoPluginWork",
        source_plugin_id="DemoPlugin",
        pinned_version="1.0.0",
    )

    assert instance.pinned_version == "1.0.0"


def test_plugin_instance_tolerates_legacy_payload_without_the_column():
    """加列之前写下的历史载荷仍能投影成实例，绑定按跟随当前版本解读。"""
    instance = PluginInstance.model_validate(
        {"instance_id": "DemoPluginWork", "source_plugin_id": "DemoPlugin"}
    )

    assert instance.pinned_version is None


# 二、按绑定解析源码目录


def test_resolve_instance_version_dir_follows_current_without_a_binding(tmp_path: Path):
    """不传实例时按插件当前版本解析。"""
    plugin_root = _two_versions(tmp_path)

    assert resolve_instance_version_dir(plugin_root, None).name == "v2_0_0"


def test_resolve_instance_version_dir_uses_the_pinned_version(tmp_path: Path):
    """钉住旧版本的实例按旧版本目录解析，而不是当前版本。"""
    plugin_root = _two_versions(tmp_path)
    instance = PluginInstance(
        instance_id="VersionedWork",
        source_plugin_id="versioned",
        pinned_version="1.0.0",
    )

    assert resolve_instance_version_dir(plugin_root, instance).name == "v1_0_0"


def test_resolve_instance_version_dir_falls_back_when_the_pinned_dir_is_gone(tmp_path: Path):
    """钉住的版本目录已不存在时回落当前版本，与加载器同一口径。"""
    plugin_root = _two_versions(tmp_path)
    instance = PluginInstance(
        instance_id="VersionedWork",
        source_plugin_id="versioned",
        pinned_version="9.9.9",
    )

    assert resolve_instance_version_dir(plugin_root, instance).name == "v2_0_0"


# 三、分身加载期的版本解析


def test_load_instance_follows_manifest_current_version_by_default(tmp_path: Path):
    """跟随当前版本时，加载器按版本元信息登记的当前版本取源码。"""
    _two_versions(tmp_path)
    instance = PluginInstance(instance_id="VersionedWork", source_plugin_id="versioned")

    plugins = _make_loader(tmp_path).load_instance(instance, _accepts_plugin)

    assert plugins[0].plugin_version == "2.0.0"
    assert plugins[0].marker == "new"


def test_load_instance_uses_the_pinned_version(tmp_path: Path):
    """钉住旧版本的分身固定加载旧版本源码，而不是清单登记的当前版本。"""
    _two_versions(tmp_path)
    instance = PluginInstance(
        instance_id="VersionedWork",
        source_plugin_id="versioned",
        pinned_version="1.0.0",
    )

    plugins = _make_loader(tmp_path).load_instance(instance, _accepts_plugin)

    assert plugins[0].plugin_version == "1.0.0"
    assert plugins[0].marker == "old"


def test_load_instance_unpinned_again_returns_to_the_current_version(tmp_path: Path):
    """解除钉版后同一个分身立刻回到跟随当前版本。"""
    _two_versions(tmp_path)
    pinned = PluginInstance(
        instance_id="VersionedWork",
        source_plugin_id="versioned",
        pinned_version="1.0.0",
    )
    loader = _make_loader(tmp_path)
    assert loader.load_instance(pinned, _accepts_plugin)[0].marker == "old"

    unpinned = pinned.model_copy(update={"pinned_version": None})
    plugins = loader.load_instance(unpinned, _accepts_plugin)

    assert plugins[0].plugin_version == "2.0.0"
    assert plugins[0].marker == "new"


def test_load_instance_falls_back_to_current_when_the_pinned_dir_is_gone(tmp_path: Path):
    """钉住的版本目录已不存在时回落当前版本，并留下点名那个版本号的告警。"""
    _write_version(tmp_path, "versioned", "2.0.0", marker="new")
    _write_manifest(tmp_path / "versioned", [("2.0.0", "v2_0_0")], current="2.0.0")
    instance = PluginInstance(
        instance_id="VersionedWork",
        source_plugin_id="versioned",
        pinned_version="9.9.9",
    )
    warnings: list[str] = []
    loader = _make_loader(tmp_path)
    loader._logger.warning = warnings.append

    plugins = loader.load_instance(instance, _accepts_plugin)

    assert plugins[0].plugin_version == "2.0.0"
    assert warnings and "9.9.9" in warnings[0]


def test_load_instance_explicit_version_overrides_the_binding(tmp_path: Path):
    """显式指定版本优先于实例自身绑定，供切换失败后以某个具体版本重试。"""
    _two_versions(tmp_path)
    instance = PluginInstance(instance_id="VersionedWork", source_plugin_id="versioned")

    plugins = _make_loader(tmp_path).load_instance(
        instance, _accepts_plugin, version="1.0.0"
    )

    assert plugins[0].plugin_version == "1.0.0"
    assert plugins[0].marker == "old"


# 四、本体加载期的版本解析


def test_load_host_follows_manifest_current_version_without_a_binding(tmp_path: Path):
    """本体从未被钉过版本时按清单登记的当前版本取源码。"""
    _two_versions(tmp_path)

    plugins = _make_loader(tmp_path).load("versioned", ["versioned"], _accepts_plugin)

    assert plugins[0].plugin_version == "2.0.0"
    assert plugins[0].marker == "new"


def test_load_host_uses_the_pinned_version(tmp_path: Path):
    """本体被钉在旧版本时固定加载旧版本源码。"""
    _two_versions(tmp_path)
    loader = _make_loader(
        tmp_path,
        host_binding=lambda plugin_id: "1.0.0" if plugin_id == "versioned" else None,
    )

    plugins = loader.load("versioned", ["versioned"], _accepts_plugin)

    assert plugins[0].plugin_version == "1.0.0"
    assert plugins[0].marker == "old"


def test_load_host_falls_back_to_current_when_the_pinned_dir_is_gone(tmp_path: Path):
    """本体钉住的版本目录已不存在时回落当前版本，而不是让本体整个加载失败。"""
    _write_version(tmp_path, "versioned", "2.0.0", marker="new")
    _write_manifest(tmp_path / "versioned", [("2.0.0", "v2_0_0")], current="2.0.0")
    warnings: list[str] = []
    loader = _make_loader(
        tmp_path,
        host_binding=lambda plugin_id: "9.9.9" if plugin_id == "versioned" else None,
    )
    loader._logger.warning = warnings.append

    plugins = loader.load("versioned", ["versioned"], _accepts_plugin)

    assert plugins[0].plugin_version == "2.0.0"
    assert warnings and "9.9.9" in warnings[0]


# 五、生命周期把显式版本穿透给加载


def _build_lifecycle(*, load_plugins) -> PluginLifecycle:
    """构造只关心版本穿透的最小生命周期实例。"""
    return PluginLifecycle(
        classes={},
        running={},
        load_plugins=load_plugins,
        loadable_plugins=lambda: ["VersionedWork"],
        plugin_config=lambda _plugin_id: {},
        auth_checker=lambda _plugin: True,
        clear_modules=lambda _plugin_id: None,
        clear_tools=lambda: None,
        enable_events=lambda _plugin: None,
        disable_events=lambda _plugin: None,
        runtime_status_writer=lambda _plugin_id, _status: None,
        database=lambda: PluginDatabase(),
        log=_logger(),
        event_sender=lambda *_args, **_kwargs: None,
    )


def _versioned_plugin_class(version: str):
    """构造声明指定版本号的最小插件类。"""
    return type(
        "VersionedWork",
        (),
        {
            "plugin_name": "版本化实例",
            "plugin_version": version,
            "init_plugin": lambda self, _config=None: None,
            "get_state": staticmethod(lambda: True),
        },
    )


def test_lifecycle_start_threads_the_explicit_version_to_load_plugins():
    """显式 version 原样传给加载入口，供版本切换重试指定一个具体版本。"""
    seen_versions: list = []

    def _load_plugins(_pid, _installed, _check, version=None):
        """记录本次收到的版本号并返回一个对应版本的插件类。"""
        seen_versions.append(version)
        return [_versioned_plugin_class(version or "2.0.0")]

    lifecycle = _build_lifecycle(load_plugins=_load_plugins)

    lifecycle.start("VersionedWork", version="1.0.0")

    assert seen_versions == ["1.0.0"]
    assert lifecycle._running["VersionedWork"].plugin_version == "1.0.0"


def test_lifecycle_start_passes_no_version_when_none_is_requested():
    """不指定版本时传空，让各实例按自身绑定解析。"""
    seen_versions: list = []

    def _load_plugins(_pid, _installed, _check, version=None):
        """记录本次收到的版本号并返回一个默认版本的插件类。"""
        seen_versions.append(version)
        return [_versioned_plugin_class("2.0.0")]

    lifecycle = _build_lifecycle(load_plugins=_load_plugins)

    lifecycle.start("VersionedWork")

    assert seen_versions == [None]
