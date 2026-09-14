"""插件安装落盘到版本目录：版本登记、存量布局迁移、失败清理与收据语义。"""

from __future__ import annotations

import asyncio
import errno
import io
import os
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.adapters.system.plugin.package import PluginPackageManager
from app.runtime.extensions.plugin import version as plugin_version_module
from app.runtime.extensions.plugin.version import (
    PLUGIN_FALLBACK_VERSION,
    PLUGIN_LAYOUT_STAGING_PREFIX,
    PLUGIN_VERSIONS_MANIFEST_NAME,
    PluginLayoutMigrationError,
    migrate_legacy_plugin_layout,
    plugin_version_dirs,
    read_plugin_versions_manifest,
    register_plugin_version,
    remove_plugin_installed_version,
    resolve_plugin_version_dir,
    write_plugin_versions_manifest,
)
from app.startup.composition.plugin import (
    _register_plugin_install_version as register_plugin_install_version,
)
from app.startup.composition.plugin import (
    _resolve_plugin_install_target as resolve_plugin_install_target,
)
from app.startup.composition.plugin import (
    _rollback_plugin_install_version as rollback_plugin_install_version,
)

PLUGIN_ID = "DemoPlugin"
LOCAL_REPO_URL = "local://demoplugin"


def _write_flat_plugin(source_root: Path, *, class_name: str, version: str | None) -> None:
    """写入一个平铺布局的最小插件源码。

    :param source_root: 源码目录
    :param class_name: 插件主类名
    :param version: 类体内声明的 plugin_version；为 None 时不声明版本号
    """
    source_root.mkdir(parents=True, exist_ok=True)
    version_line = f"    plugin_version = {version!r}\n" if version else ""
    (source_root / "__init__.py").write_text(
        f"class {class_name}:\n{version_line}    plugin_name = {class_name!r}\n",
        encoding="utf-8",
    )


def _place_version_dir(plugin_root: Path, version: str, *, marker: str) -> Path:
    """在插件目录下直接放一个已就位的版本目录并登记，模拟此前装好的版本。

    :param plugin_root: 插件根目录
    :param version: 版本号
    :param marker: 写入 marker.txt 的内容，供断言分辨是哪一份源码
    :return: 版本目录
    """
    directory = plugin_root / plugin_version_module.plugin_version_dir_name(version)
    _write_flat_plugin(directory, class_name="DemoPlugin", version=version)
    (directory / "marker.txt").write_text(marker, encoding="utf-8")
    register_plugin_version(plugin_root, version, "market")
    return directory


def _versioned_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    source: object | None = None,
) -> tuple[PluginPackageManager, Path]:
    """构造接了真实版本目录端口的包管理器，所有落盘隔离在 tmp_path 内。

    :param monkeypatch: pytest monkeypatch 夹具
    :param tmp_path: 隔离运行目录的临时根
    :param source: 市场来源端口；为空时用空 Mock 占位
    :return: (包管理器, 插件安装根目录)
    """
    plugins_root = tmp_path / "app" / "plugins"
    settings = SimpleNamespace(
        ROOT_PATH=tmp_path,
        TEMP_PATH=tmp_path / "temp",
        CONFIG_PATH=tmp_path / "config",
        VERSION_FLAG="v2",
        REPO_GITHUB_HEADERS=lambda repo: {},
    )
    monkeypatch.setattr(
        "app.adapters.system.plugin.package.get_runtime_setting",
        lambda key: getattr(settings, key),
    )
    manager = PluginPackageManager(
        source=source or Mock(),
        plugin_root=plugins_root,
        install_target_resolver=resolve_plugin_install_target,
        install_version_registrar=register_plugin_install_version,
        install_version_rollback=rollback_plugin_install_version,
    )
    return manager, plugins_root


def _local_source_port(source_dir: Path) -> Mock:
    """构造只声明本地安装所需方法的市场来源端口替身。"""
    source_port = Mock()
    source_port.is_local_repo_url.return_value = True
    source_port.parse_local_repo_url.return_value = PLUGIN_ID
    source_port.parse_local_repo_path.return_value = None
    source_port.parse_local_repo_package_version.return_value = None
    source_port.get_local_plugin_candidate.return_value = {"path": str(source_dir)}
    source_port.check_plugin_system_version.return_value = (True, "")
    return source_port


def _local_manager(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, version: str | None
) -> tuple[PluginPackageManager, Path, Path]:
    """准备一个可直接执行本地安装的包管理器及其待装源码。

    :return: (包管理器, 插件安装根目录, 插件根目录)
    """
    source_dir = tmp_path / "repo" / "demoplugin"
    _write_flat_plugin(source_dir, class_name=PLUGIN_ID, version=version)
    manager, plugins_root = _versioned_manager(
        monkeypatch, tmp_path, source=_local_source_port(source_dir)
    )
    return manager, plugins_root, plugins_root / PLUGIN_ID.lower()


def _fail_dependencies(monkeypatch: pytest.MonkeyPatch, manager: PluginPackageManager) -> None:
    """把依赖安装固定为失败，用来触发落位之后的失败清理路径。"""
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__install_dependencies_if_required",
        lambda *_args: (True, False, "dependency failed"),
    )

    async def async_dependencies(*_args: object) -> tuple[bool, bool, str]:
        """异步流程复用同一失败结论。"""
        return True, False, "dependency failed"

    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__async_install_dependencies_if_required",
        async_dependencies,
    )


def _break_replace_under(monkeypatch: pytest.MonkeyPatch, root: Path, code: int) -> None:
    """让源路径位于给定目录内的原子改名失败，模拟跨文件系统或权限受限。"""
    original = Path.replace

    def guarded(self: Path, target):
        """只拦截位于给定目录内的源路径，其它改名仍走真实实现。"""
        if self.is_relative_to(root):
            raise OSError(code, "simulated")
        return original(self, target)

    monkeypatch.setattr(Path, "replace", guarded)


def _zip_bytes(files: dict[str, str]) -> bytes:
    """把文件名到文本内容的映射打包为内存中的 zip 字节串。"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


# 一、版本元信息登记


def test_register_plugin_version_writes_manifest_and_sets_current(tmp_path: Path) -> None:
    """首次登记写出版本条目并把它置为当前版本。"""
    plugin_root = tmp_path / "demoplugin"
    plugin_root.mkdir()

    dir_name, previous_current = register_plugin_version(plugin_root, "1.2.0", "market")

    manifest = read_plugin_versions_manifest(plugin_root)
    assert dir_name == "v1_2_0"
    assert previous_current is None
    assert manifest["current"] == "1.2.0"
    assert [entry["version"] for entry in manifest["versions"]] == ["1.2.0"]
    assert manifest["versions"][0]["source"] == "market"


def test_register_plugin_version_replaces_the_entry_for_the_same_version(
    tmp_path: Path,
) -> None:
    """同版本重复登记只更新那一条，不追加重复条目。"""
    plugin_root = tmp_path / "demoplugin"
    plugin_root.mkdir()
    register_plugin_version(plugin_root, "1.0.0", "market")

    _, previous_current = register_plugin_version(plugin_root, "1.0.0", "local")

    manifest = read_plugin_versions_manifest(plugin_root)
    assert previous_current == "1.0.0"
    assert [entry["version"] for entry in manifest["versions"]] == ["1.0.0"]
    assert manifest["versions"][0]["source"] == "local"


def test_register_plugin_version_keeps_siblings_and_returns_previous_current(
    tmp_path: Path,
) -> None:
    """登记新版本保留既有版本，并如实返回登记前的当前版本。"""
    plugin_root = tmp_path / "demoplugin"
    plugin_root.mkdir()
    register_plugin_version(plugin_root, "1.0.0", "market")

    _, previous_current = register_plugin_version(plugin_root, "2.0.0", "market")

    manifest = read_plugin_versions_manifest(plugin_root)
    assert previous_current == "1.0.0"
    assert manifest["current"] == "2.0.0"
    assert {entry["version"] for entry in manifest["versions"]} == {"1.0.0", "2.0.0"}


def test_register_plugin_version_adopts_version_dirs_missing_from_the_manifest(
    tmp_path: Path,
) -> None:
    """磁盘上有、清单里没有的版本目录会在下一次登记时被收编。"""
    plugin_root = tmp_path / "demoplugin"
    orphan = plugin_root / "v1_0_0"
    _write_flat_plugin(orphan, class_name="DemoPlugin", version="1.0.0")

    register_plugin_version(plugin_root, "2.0.0", "market")

    manifest = read_plugin_versions_manifest(plugin_root)
    adopted = {entry["version"]: entry for entry in manifest["versions"]}
    assert set(adopted) == {"1.0.0", "2.0.0"}
    assert adopted["1.0.0"]["source"] == "discovered"
    assert adopted["1.0.0"]["installed_at"] is not None
    assert manifest["current"] == "2.0.0"


def test_register_plugin_version_rejects_an_illegal_version(tmp_path: Path) -> None:
    """版本号无法映射为目录名时直接拒绝，不写出半份元信息。"""
    plugin_root = tmp_path / "demoplugin"
    plugin_root.mkdir()

    with pytest.raises(ValueError):
        register_plugin_version(plugin_root, "1_0_0", "market")

    assert not (plugin_root / PLUGIN_VERSIONS_MANIFEST_NAME).exists()


def test_manifest_write_failure_keeps_the_previous_manifest_readable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """元信息写入中途失败时旧清单仍完整可读，且不留临时文件。"""
    plugin_root = tmp_path / "demoplugin"
    plugin_root.mkdir()
    write_plugin_versions_manifest(
        plugin_root, [{"version": "1.0.0", "directory": "v1_0_0"}], "1.0.0"
    )
    original_write_text = Path.write_text

    def guarded(self: Path, *args: object, **kwargs: object):
        """模拟写到一半磁盘写满：先落半份内容再抛错。"""
        if self.name.startswith(f".{PLUGIN_VERSIONS_MANIFEST_NAME}."):
            original_write_text(self, "{truncated", encoding="utf-8")
            raise OSError(errno.ENOSPC, "no space left on device")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", guarded)

    with pytest.raises(OSError):
        write_plugin_versions_manifest(
            plugin_root, [{"version": "2.0.0", "directory": "v2_0_0"}], "2.0.0"
        )

    assert read_plugin_versions_manifest(plugin_root)["current"] == "1.0.0"
    assert not list(plugin_root.glob(f".{PLUGIN_VERSIONS_MANIFEST_NAME}.*"))


# 二、存量平铺布局迁移


def test_legacy_flat_layout_is_migrated_into_a_version_dir(tmp_path: Path) -> None:
    """存量平铺源码整体搬进版本目录，并登记为当前版本。"""
    plugin_root = tmp_path / "demoplugin"
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="1.4.0")
    (plugin_root / "assets").mkdir()
    (plugin_root / "assets" / "logo.png").write_bytes(b"png")

    migrated = migrate_legacy_plugin_layout(plugin_root)

    assert migrated == plugin_root / "v1_4_0"
    assert (migrated / "__init__.py").is_file()
    assert (migrated / "assets" / "logo.png").read_bytes() == b"png"
    assert not (plugin_root / "__init__.py").exists()
    assert read_plugin_versions_manifest(plugin_root)["current"] == "1.4.0"
    assert read_plugin_versions_manifest(plugin_root)["versions"][0]["source"] == "migrated"


def test_legacy_layout_without_a_declared_version_uses_the_fallback_version(
    tmp_path: Path,
) -> None:
    """没有声明版本号的存量插件按兜底版本号迁移，而不是拒绝迁移。"""
    plugin_root = tmp_path / "demoplugin"
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version=None)

    migrated = migrate_legacy_plugin_layout(plugin_root)

    assert migrated == plugin_root / "v0_0_0"
    assert read_plugin_versions_manifest(plugin_root)["current"] == PLUGIN_FALLBACK_VERSION


def test_migration_is_a_no_op_when_there_is_nothing_to_migrate(tmp_path: Path) -> None:
    """已是版本化布局时迁移不动手，也不重写元信息。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    before = (plugin_root / PLUGIN_VERSIONS_MANIFEST_NAME).read_text(encoding="utf-8")

    assert migrate_legacy_plugin_layout(plugin_root) is None
    assert (plugin_root / PLUGIN_VERSIONS_MANIFEST_NAME).read_text(encoding="utf-8") == before


def test_version_dirs_and_the_manifest_are_never_migrated_as_source(
    tmp_path: Path,
) -> None:
    """已有版本目录与元信息属于布局自身，不会被当成待迁移的存量源码搬走。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="2.0.0")

    migrated = migrate_legacy_plugin_layout(plugin_root)

    assert migrated == plugin_root / "v2_0_0"
    assert (plugin_root / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert not (plugin_root / "v2_0_0" / "v1_0_0").exists()
    assert not (plugin_root / "v2_0_0" / PLUGIN_VERSIONS_MANIFEST_NAME).exists()


def test_interrupted_migration_is_resumed_with_the_declared_version(
    tmp_path: Path,
) -> None:
    """上次中断留下的中转目录会被续做，且版本号仍按主模块声明取。"""
    plugin_root = tmp_path / "demoplugin"
    staging = plugin_root / f"{PLUGIN_LAYOUT_STAGING_PREFIX}deadbeef"
    _write_flat_plugin(staging, class_name="DemoPlugin", version="2.5.0")
    (plugin_root / "assets").mkdir()
    (plugin_root / "assets" / "logo.png").write_bytes(b"png")

    migrated = migrate_legacy_plugin_layout(plugin_root)

    assert migrated == plugin_root / "v2_5_0"
    assert (migrated / "__init__.py").is_file()
    assert (migrated / "assets" / "logo.png").read_bytes() == b"png"
    assert not staging.exists()
    assert read_plugin_versions_manifest(plugin_root)["current"] == "2.5.0"


def test_interrupted_migration_leaves_no_half_importable_plugin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """搬迁中断时插件根目录不得留下"有主模块但源码残缺"的半份平铺布局。"""
    plugin_root = tmp_path / "demoplugin"
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="1.0.0")
    (plugin_root / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    original_rename = os.rename
    moved: list[str] = []

    def guarded(src, dst):
        """第一条搬完就中断，复现搬到一半被杀的现场。"""
        if moved:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        moved.append(Path(str(src)).name)
        original_rename(src, dst)

    monkeypatch.setattr(plugin_version_module.os, "rename", guarded)

    with pytest.raises(PluginLayoutMigrationError):
        migrate_legacy_plugin_layout(plugin_root)

    assert moved == ["__init__.py"]
    assert not (plugin_root / "__init__.py").exists()
    assert (plugin_root / "helper.py").is_file()


def test_aborted_migration_can_still_be_resumed_after_the_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """迁移失败留下的中转目录在下一次调用时续做完整，源码一件不丢。"""
    plugin_root = tmp_path / "demoplugin"
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="1.0.0")
    (plugin_root / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    original_rename = os.rename
    moved: list[str] = []

    def guarded(src, dst):
        """只放行第一条改名，之后一律伪造跨设备失败。"""
        if moved:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        moved.append(Path(str(src)).name)
        original_rename(src, dst)

    monkeypatch.setattr(plugin_version_module.os, "rename", guarded)
    with pytest.raises(PluginLayoutMigrationError):
        migrate_legacy_plugin_layout(plugin_root)
    monkeypatch.setattr(plugin_version_module.os, "rename", original_rename)

    migrated = migrate_legacy_plugin_layout(plugin_root)

    assert migrated == plugin_root / "v1_0_0"
    assert (migrated / "__init__.py").is_file()
    assert (migrated / "helper.py").read_text(encoding="utf-8") == "HELPER = 1\n"
    assert not list(plugin_root.glob(f"{PLUGIN_LAYOUT_STAGING_PREFIX}*"))
    assert read_plugin_versions_manifest(plugin_root)["current"] == "1.0.0"


def test_cross_filesystem_rename_aborts_migration_instead_of_copying(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """跨设备无法改名时放弃迁移并如实抛出，不退化为复制加删除。"""
    plugin_root = tmp_path / "demoplugin"
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="1.0.0")

    def refuse(*_args: object, **_kwargs: object) -> None:
        """模拟 overlayfs 上的跨设备改名失败。"""
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(plugin_version_module.os, "rename", refuse)

    with pytest.raises(PluginLayoutMigrationError):
        migrate_legacy_plugin_layout(plugin_root)

    assert (plugin_root / "__init__.py").is_file()
    assert not (plugin_root / "v1_0_0").exists()
    assert not read_plugin_versions_manifest(plugin_root)


def test_migration_refuses_to_merge_into_an_existing_version_dir(tmp_path: Path) -> None:
    """待迁移版本目录已存在时拒绝合并，避免两份源码互相覆盖。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    _write_flat_plugin(plugin_root, class_name="DemoPlugin", version="1.0.0")

    with pytest.raises(PluginLayoutMigrationError):
        migrate_legacy_plugin_layout(plugin_root)

    assert (plugin_root / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert (plugin_root / "__init__.py").is_file()


# 三、安装落盘到版本目录


def test_local_install_lands_in_a_version_directory_and_records_the_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """本地安装把声明了版本号的源码落到版本目录，并登记来源标签 local。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="1.0.0")

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    manifest = read_plugin_versions_manifest(plugin_dir)
    assert (plugin_dir / "v1_0_0" / "__init__.py").is_file()
    assert not (plugin_dir / "__init__.py").exists()
    assert manifest["current"] == "1.0.0"
    assert manifest["versions"][-1]["source"] == "local"


def test_package_manager_without_version_ports_installs_flat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """未注入版本目录端口时安装逐字保持平铺覆盖行为，不产生任何版本化痕迹。"""
    source_dir = tmp_path / "repo" / "demoplugin"
    _write_flat_plugin(source_dir, class_name=PLUGIN_ID, version="1.0.0")
    _, plugins_root = _versioned_manager(monkeypatch, tmp_path)
    manager = PluginPackageManager(
        source=_local_source_port(source_dir), plugin_root=plugins_root
    )

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    plugin_dir = plugins_root / PLUGIN_ID.lower()
    assert (plugin_dir / "__init__.py").is_file()
    assert not plugin_version_dirs(plugin_dir)
    assert not (plugin_dir / PLUGIN_VERSIONS_MANIFEST_NAME).exists()


def test_release_install_lands_in_a_version_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Release 制品安装同样落到版本目录。"""
    manager, plugins_root = _versioned_manager(monkeypatch, tmp_path)
    release_tag = "DemoPlugin_v3.1.0"
    monkeypatch.setattr(manager, "is_local_repo_url", lambda _repo_url: False)
    monkeypatch.setattr(manager, "get_repo_info", lambda _repo_url: ("demo", "repo"))
    monkeypatch.setattr(manager, "get_plugin_package_version", lambda *_args: "v2")
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__get_plugin_meta",
        lambda *_args: {"release": True, "version": "3.1.0"},
    )
    responses = iter(
        [
            SimpleNamespace(
                status_code=200,
                json=lambda: {"assets": [{"name": f"{release_tag.lower()}.zip", "id": 7}]},
            ),
            SimpleNamespace(
                status_code=200,
                content=_zip_bytes(
                    {"__init__.py": "class DemoPlugin:\n    plugin_version = '3.1.0'\n"}
                ),
            ),
        ]
    )
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__request_with_fallback",
        lambda *_args, **_kwargs: next(responses),
    )

    assert manager.install_raw(PLUGIN_ID, "https://github.com/demo/repo") == (True, "")

    plugin_dir = plugins_root / PLUGIN_ID.lower()
    assert (plugin_dir / "v3_1_0" / "__init__.py").is_file()
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "3.1.0"


def test_filelist_install_lands_in_a_version_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """文件列表方式安装把源码落到版本目录并登记来源标签 market。"""
    manager, plugins_root = _versioned_manager(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, "is_local_repo_url", lambda _repo_url: False)
    monkeypatch.setattr(manager, "get_repo_info", lambda _repo_url: ("demo", "repo"))
    monkeypatch.setattr(manager, "get_plugin_package_version", lambda *_args: "v2")
    monkeypatch.setattr(
        manager, "_PluginPackageManager__get_plugin_meta", lambda *_args: {"release": False}
    )
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__get_file_list",
        lambda *_args: (
            [
                {
                    "path": "plugins.v2/demoplugin/__init__.py",
                    "download_url": "https://example.invalid/init",
                }
            ],
            "",
        ),
    )
    monkeypatch.setattr(
        manager,
        "_PluginPackageManager__request_with_fallback",
        lambda *_args, **_kwargs: SimpleNamespace(
            status_code=200,
            content=b"class DemoPlugin:\n    plugin_version = '4.2.0'\n",
        ),
    )

    assert manager.install_raw(PLUGIN_ID, "https://github.com/demo/repo") == (True, "")

    plugin_dir = plugins_root / PLUGIN_ID.lower()
    assert (plugin_dir / "v4_2_0" / "__init__.py").is_file()
    assert read_plugin_versions_manifest(plugin_dir)["versions"][-1]["source"] == "market"


def test_async_filelist_install_lands_in_a_version_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """异步安装流程与同步流程落到同一个版本目录，登记同样生效。"""
    manager, plugins_root = _versioned_manager(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, "is_local_repo_url", lambda _repo_url: False)
    monkeypatch.setattr(manager, "get_repo_info", lambda _repo_url: ("demo", "repo"))

    async def package_version(*_args: object) -> str:
        """异步入口固定索引代际。"""
        return "v2"

    async def meta(*_args: object) -> dict:
        """异步入口固定插件元数据。"""
        return {"release": False}

    async def file_list(*_args: object):
        """异步入口固定文件列表。"""
        return (
            [
                {
                    "path": "plugins.v2/demoplugin/__init__.py",
                    "download_url": "https://example.invalid/init",
                }
            ],
            "",
        )

    async def request(*_args: object, **_kwargs: object):
        """异步入口固定下载响应。"""
        return SimpleNamespace(
            status_code=200,
            content=b"class DemoPlugin:\n    plugin_version = '5.0.0'\n",
        )

    monkeypatch.setattr(manager, "async_get_plugin_package_version", package_version)
    monkeypatch.setattr(manager, "_PluginPackageManager__async_get_plugin_meta", meta)
    monkeypatch.setattr(manager, "_PluginPackageManager__async_get_file_list", file_list)
    monkeypatch.setattr(
        manager, "_PluginPackageManager__async_request_with_fallback", request
    )

    result = asyncio.run(
        manager.async_install_raw(pid=PLUGIN_ID, repo_url="https://github.com/demo/repo")
    )

    assert result == (True, "")
    plugin_dir = plugins_root / PLUGIN_ID.lower()
    assert (plugin_dir / "v5_0_0" / "__init__.py").is_file()
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "5.0.0"


def test_install_without_a_declared_version_stays_flat_and_writes_no_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """没有声明版本号的插件继续按平铺布局安装，不凭空造版本目录。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version=None)

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert (plugin_dir / "__init__.py").is_file()
    assert not plugin_version_dirs(plugin_dir)
    assert not (plugin_dir / PLUGIN_VERSIONS_MANIFEST_NAME).exists()


def test_same_version_reinstall_over_a_flat_layout_stays_flat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """存量平铺插件重装同一版本是一次原地重装，不触发版本目录迁移。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="1.0.0")
    _write_flat_plugin(plugin_dir, class_name=PLUGIN_ID, version="1.0.0")

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert (plugin_dir / "__init__.py").is_file()
    assert not plugin_version_dirs(plugin_dir)


def test_installing_a_second_version_migrates_the_legacy_layout_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """存量平铺插件装另一个版本时先把自己迁进版本目录，两个版本并存。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _write_flat_plugin(plugin_dir, class_name=PLUGIN_ID, version="1.0.0")
    (plugin_dir / "marker.txt").write_text("stable", encoding="utf-8")

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    manifest = read_plugin_versions_manifest(plugin_dir)
    assert set(plugin_version_dirs(plugin_dir)) == {"1.0.0", "2.0.0"}
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert manifest["current"] == "2.0.0"
    assert resolve_plugin_version_dir(plugin_dir) == plugin_dir / "v2_0_0"


def test_reinstalling_an_existing_version_directory_replaces_its_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """重装一个已装版本会整体替换该版本目录，兄弟版本一件不动。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _place_version_dir(plugin_dir, "2.0.0", marker="stale")

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert not (plugin_dir / "v2_0_0" / "marker.txt").exists()
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "2.0.0"


def test_install_adopts_an_orphan_version_dir_left_by_a_lost_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """清单丢失、磁盘还留着旧版本目录时，新安装把它收编而不是抹掉。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _write_flat_plugin(plugin_dir / "v1_0_0", class_name=PLUGIN_ID, version="1.0.0")

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    manifest = read_plugin_versions_manifest(plugin_dir)
    assert {entry["version"] for entry in manifest["versions"]} == {"1.0.0", "2.0.0"}
    assert manifest["current"] == "2.0.0"


# 四、安装失败时旧版本仍可加载


def test_dependency_failure_only_removes_the_new_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """依赖安装失败只清理本次版本目录，旧版本源码与当前版本都复原。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _fail_dependencies(monkeypatch, manager)

    success, message = manager.install_local_raw(
        PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True
    )

    assert (success, message) == (False, "dependency failed")
    assert not (plugin_dir / "v2_0_0").exists()
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "1.0.0"
    assert resolve_plugin_version_dir(plugin_dir) == plugin_dir / "v1_0_0"


def test_async_dependency_failure_only_removes_the_new_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """异步流程的失败清理范围与同步一致。"""
    manager, plugins_root = _versioned_manager(monkeypatch, tmp_path)
    plugin_dir = plugins_root / PLUGIN_ID.lower()
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _fail_dependencies(monkeypatch, manager)

    async def prepare(staging_dir: Path) -> tuple[bool, str]:
        """把待装的新版本源码放进暂存目录。"""
        _write_flat_plugin(staging_dir, class_name=PLUGIN_ID, version="2.0.0")
        return True, ""

    result = asyncio.run(
        manager._PluginPackageManager__install_flow_async(  # noqa: SLF001
            PLUGIN_ID, True, prepare
        )
    )

    assert result == (False, "dependency failed")
    assert not (plugin_dir / "v2_0_0").exists()
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "1.0.0"


def test_install_failure_restores_the_version_that_was_current_before_this_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """失败清理精确复原登记前的当前版本，而不是取剩余版本里最高的那个。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "3.0.0", marker="newest")
    _place_version_dir(plugin_dir, "1.5.0", marker="pinned")
    _fail_dependencies(monkeypatch, manager)

    manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True)

    manifest = read_plugin_versions_manifest(plugin_dir)
    assert manifest["current"] == "1.5.0"
    assert set(plugin_version_dirs(plugin_dir)) == {"1.5.0", "3.0.0"}


def test_first_ever_version_install_failure_leaves_no_empty_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """插件第一个版本安装失败时连插件目录一起清掉，不留空壳与空清单。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="1.0.0")
    _fail_dependencies(monkeypatch, manager)

    manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True)

    assert not plugin_dir.exists()


def test_flat_layout_install_failure_still_removes_the_whole_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """没有版本号的插件安装失败时沿用清理整个插件目录的既有行为。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version=None)
    _fail_dependencies(monkeypatch, manager)

    manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True)

    assert not plugin_dir.exists()


def test_target_resolver_failure_keeps_the_installed_version_loadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """目标目录决策失败时不写任何内容，已装版本原样可加载。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    monkeypatch.setattr(
        manager,
        "_install_target_resolver",
        Mock(side_effect=RuntimeError("resolver exploded")),
    )

    success, message = manager.install_local_raw(
        PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True
    )

    assert not success
    assert "解析插件安装目标失败" in message
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert set(plugin_version_dirs(plugin_dir)) == {"1.0.0"}
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "1.0.0"


def test_registration_failure_after_a_successful_swap_removes_the_new_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """换入成功但元信息登记失败时清掉新版本目录，旧版本与当前版本不受影响。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    monkeypatch.setattr(
        manager,
        "_install_version_registrar",
        Mock(side_effect=RuntimeError("registrar exploded")),
    )

    success, message = manager.install_local_raw(
        PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True
    )

    assert not success
    assert "登记插件版本元信息失败" in message
    assert not (plugin_dir / "v2_0_0").exists()
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "1.0.0"


def test_swap_failure_installing_a_new_version_leaves_existing_versions_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """换入新版本失败时既有版本逐字节完好，失败清理不得越界。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _break_replace_under(
        monkeypatch, tmp_path / "temp" / "plugin_install_staging", errno.EACCES
    )

    success, message = manager.install_local_raw(
        PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True
    )

    assert not success
    assert "写入插件内容失败" in message
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert not (plugin_dir / "v2_0_0").exists()
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "1.0.0"


def test_swap_into_a_version_directory_falls_back_to_copy_across_filesystems(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """暂存目录与插件目录跨文件系统时换入退化为复制，版本目录结果一致。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _break_replace_under(
        monkeypatch, tmp_path / "temp" / "plugin_install_staging", errno.EXDEV
    )

    assert manager.install_local_raw(
        PLUGIN_ID, repo_url=LOCAL_REPO_URL, force_install=True
    ) == (True, "")

    assert (plugin_dir / "v2_0_0" / "__init__.py").is_file()
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"
    assert read_plugin_versions_manifest(plugin_dir)["current"] == "2.0.0"


def test_swap_failure_reinstalling_an_existing_version_restores_it_from_backup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """重装同一版本换入到一半失败时，整根备份把该版本的原内容还原回来。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    _place_version_dir(plugin_dir, "2.0.0", marker="original")
    target = plugin_dir / "v2_0_0"
    original_replace = Path.replace
    original_rmtree = shutil.rmtree

    def guarded_replace(self: Path, other):
        """暂存目录与旧版本目录都无法原子改名，逼出复制加删除的退化路径。"""
        if self.is_relative_to(tmp_path / "temp" / "plugin_install_staging") or self == target:
            raise OSError(errno.EXDEV, "simulated")
        return original_replace(self, other)

    def guarded_rmtree(path, *args, **kwargs):
        """删除旧版本目录时删到一半失败，制造"运行目录未恢复"的现场。"""
        if Path(path) == target:
            for child in sorted(Path(path).iterdir(), reverse=True):
                if child.is_file():
                    child.unlink()
                    break
            raise OSError(errno.EIO, "simulated")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", guarded_replace)
    monkeypatch.setattr("app.adapters.system.plugin.package.shutil.rmtree", guarded_rmtree)

    success, message = manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL)

    assert not success
    assert "写入插件内容失败" in message
    assert (target / "marker.txt").read_text(encoding="utf-8") == "original"
    assert (plugin_dir / "v1_0_0" / "marker.txt").read_text(encoding="utf-8") == "stable"


# 五、版本回滚


def test_remove_plugin_installed_version_keeps_siblings_and_restores_previous_current(
    tmp_path: Path,
) -> None:
    """回滚只摘除指定版本，当前版本精确复原为登记前的值。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    _place_version_dir(plugin_root, "3.0.0", marker="newest")
    _, previous_current = register_plugin_version(plugin_root, "2.0.0", "market")
    _write_flat_plugin(plugin_root / "v2_0_0", class_name="DemoPlugin", version="2.0.0")

    remove_plugin_installed_version(plugin_root, "2.0.0", previous_current)

    manifest = read_plugin_versions_manifest(plugin_root)
    assert manifest["current"] == "3.0.0"
    assert {entry["version"] for entry in manifest["versions"]} == {"1.0.0", "3.0.0"}
    assert not (plugin_root / "v2_0_0").exists()


def test_remove_plugin_installed_version_empties_current_when_it_is_gone(
    tmp_path: Path,
) -> None:
    """登记前的当前版本已不在剩余版本里时当前版本置空，不去猜一个版本号。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    _, _ = register_plugin_version(plugin_root, "2.0.0", "market")
    _write_flat_plugin(plugin_root / "v2_0_0", class_name="DemoPlugin", version="2.0.0")

    remove_plugin_installed_version(plugin_root, "2.0.0", "9.9.9")

    assert read_plugin_versions_manifest(plugin_root)["current"] is None
    assert set(plugin_version_dirs(plugin_root)) == {"1.0.0"}


def test_remove_plugin_installed_version_deletes_the_empty_plugin_root(
    tmp_path: Path,
) -> None:
    """回滚掉唯一版本后插件目录是空壳，整根删除不留失败残迹。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="only")

    remove_plugin_installed_version(plugin_root, "1.0.0", None)

    assert not plugin_root.exists()


def test_remove_plugin_installed_version_is_a_no_op_for_a_version_never_placed(
    tmp_path: Path,
) -> None:
    """回滚一个从未落盘的版本不得牵连已装版本。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")

    remove_plugin_installed_version(plugin_root, "2.0.0", "1.0.0")

    assert set(plugin_version_dirs(plugin_root)) == {"1.0.0"}
    assert read_plugin_versions_manifest(plugin_root)["current"] == "1.0.0"


def test_remove_plugin_installed_version_refuses_to_delete_a_non_version_dir(
    tmp_path: Path,
) -> None:
    """元信息登记的目录名与版本号对不上时拒绝删除，不误删普通目录。"""
    plugin_root = tmp_path / "demoplugin"
    _place_version_dir(plugin_root, "1.0.0", marker="stable")
    wheels = plugin_root / "wheels"
    wheels.mkdir()

    remove_plugin_installed_version(plugin_root, "2.0.0", "1.0.0")

    assert wheels.is_dir()
    assert (plugin_root / "v1_0_0").is_dir()


# 六、载荷收据语义


def test_payload_receipt_covers_sibling_versions_and_the_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """收据覆盖整个插件根目录：新增一个兄弟版本目录会改变收据。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="2.0.0")
    _place_version_dir(plugin_dir, "1.0.0", marker="stable")
    before = manager.payload_receipt(PLUGIN_ID)

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert manager.payload_receipt(PLUGIN_ID) != before


def test_flat_same_version_reinstall_keeps_the_payload_receipt_stable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """平铺布局重装同一版本不造版本目录，收据与安装前逐字一致。"""
    manager, _, plugin_dir = _local_manager(monkeypatch, tmp_path, version="1.0.0")
    _write_flat_plugin(plugin_dir, class_name=PLUGIN_ID, version="1.0.0")
    before = manager.payload_receipt(PLUGIN_ID)

    assert manager.install_local_raw(PLUGIN_ID, repo_url=LOCAL_REPO_URL) == (True, "")

    assert manager.payload_receipt(PLUGIN_ID) == before
