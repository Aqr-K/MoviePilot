"""插件版本目录回收：保留判据、保留窗口、孤儿清理、删除安全校验与并发拒绝测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.runtime.extensions.plugin import version as plugin_version_module
from app.runtime.extensions.plugin.version import (
    PLUGIN_VERSION_KEPT_CURRENT,
    PLUGIN_VERSION_KEPT_DELETE_FAILED,
    PLUGIN_VERSION_KEPT_PENDING_INSTALL,
    PLUGIN_VERSION_KEPT_REFERENCED,
    PLUGIN_VERSION_RETENTION_WINDOW,
    _delete_plugin_version_dir,
    plugin_version_dir_name,
    read_plugin_versions_manifest,
    recycle_plugin_version_directories,
    register_plugin_version,
    resolve_instance_version_dir,
    resolve_plugin_version_dir,
    write_plugin_versions_manifest,
)
from app.schemas.plugin import PluginInstance
from tests.test_plugin_version_binding import (  # noqa: F401 - 复用第四层已有的绑定脚手架
    CLONE_ID,
    PLUGIN_ID,
    _clone,
    _Harness,
    _host,
)


def _install_version(plugin_root: Path, version: str) -> Path:
    """在插件目录下落地一个最小版本目录并登记到已装版本元信息。

    :param plugin_root: 插件源码根目录
    :param version: 版本号，登记后成为元信息的当前版本
    :return: 落地的版本目录
    """
    version_dir = plugin_root / plugin_version_dir_name(version)
    version_dir.mkdir(parents=True)
    (version_dir / "__init__.py").write_text(
        f"plugin_version = {version!r}\n", encoding="utf-8"
    )
    register_plugin_version(plugin_root, version, source="test")
    return version_dir


def _stamp_installed_at(plugin_root: Path, stamps: dict[str, str]) -> None:
    """改写元信息里各版本的登记时间，消除真实时钟带来的顺序不确定性。

    :param plugin_root: 插件源码根目录
    :param stamps: 版本号到 ISO8601 时间字符串的映射
    """
    manifest = read_plugin_versions_manifest(plugin_root)
    for entry in manifest["versions"]:
        if entry["version"] in stamps:
            entry["installed_at"] = stamps[entry["version"]]
    write_plugin_versions_manifest(plugin_root, manifest["versions"], manifest["current"])


def _orphan_version_dir(plugin_root: Path, version: str) -> Path:
    """造出一个磁盘上存在、元信息却没登记的孤儿版本目录。

    还原的是真实来源：一次失败安装回滚时元信息已经摘掉该版本、当前版本精确复原为
    登记它之前那一个，删目录却失败了。

    :param plugin_root: 插件源码根目录
    :param version: 孤儿版本号
    :return: 孤儿版本目录
    """
    previous_current = read_plugin_versions_manifest(plugin_root).get("current")
    orphan = _install_version(plugin_root, version)
    manifest = read_plugin_versions_manifest(plugin_root)
    remaining = [entry for entry in manifest["versions"] if entry["version"] != version]
    write_plugin_versions_manifest(plugin_root, remaining, previous_current)
    return orphan


# 一、保留判据：当前版本、被引用版本


def test_current_version_is_never_recycled(tmp_path: Path) -> None:
    """当前安装版本即使无实例引用、保留窗口为 0 也不删除。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    assert outcome["removed"] == []
    assert outcome["kept"]["1.0.0"] == PLUGIN_VERSION_KEPT_CURRENT
    assert (plugin_root / "v1_0_0").is_dir()


def test_referenced_version_is_not_recycled(tmp_path: Path) -> None:
    """被实例引用的版本不删除，即便它既不是当前版本也不在保留窗口内。"""
    plugin_root = tmp_path / "sample"
    for version in ("1.0.0", "2.0.0", "3.0.0"):
        _install_version(plugin_root, version)

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions={"1.0.0"}, retention=0
    )

    assert outcome["removed"] == ["2.0.0"]
    assert outcome["kept"]["1.0.0"] == PLUGIN_VERSION_KEPT_REFERENCED
    assert (plugin_root / "v1_0_0").is_dir()
    assert (plugin_root / "v3_0_0").is_dir()
    assert not (plugin_root / "v2_0_0").exists()


def test_manifest_drops_removed_versions_and_keeps_the_current_pointer(
    tmp_path: Path,
) -> None:
    """回收后元信息同步剔除被删版本的条目，当前版本指针保持不变。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")

    recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    manifest = read_plugin_versions_manifest(plugin_root)
    assert {entry["version"] for entry in manifest["versions"]} == {"2.0.0"}
    assert manifest["current"] == "2.0.0"


def test_a_no_op_recycle_leaves_the_manifest_byte_identical(tmp_path: Path) -> None:
    """没有删掉任何版本时元信息一个字节都不改写，载荷收据因此不受影响。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")
    manifest_file = plugin_root / "versions.json"
    before = manifest_file.read_bytes()

    outcome = recycle_plugin_version_directories(plugin_root, referenced_versions=set())

    assert outcome["removed"] == []
    assert manifest_file.read_bytes() == before


def test_no_version_dirs_on_disk_is_a_no_op(tmp_path: Path) -> None:
    """磁盘上没有任何版本目录时直接返回空结果，不报错也不建元信息。"""
    plugin_root = tmp_path / "empty"
    plugin_root.mkdir()

    outcome = recycle_plugin_version_directories(plugin_root, referenced_versions=set())

    assert outcome == {"removed": [], "kept": {}}
    assert not (plugin_root / "versions.json").exists()


# 二、保留窗口


def test_retention_window_keeps_the_n_most_recent_versions(tmp_path: Path) -> None:
    """保留窗口按登记时间保留最近 N 个版本，窗口外且无引用的旧版本被回收。"""
    plugin_root = tmp_path / "sample"
    for version in ("1.0.0", "2.0.0", "3.0.0"):
        _install_version(plugin_root, version)
    _stamp_installed_at(
        plugin_root,
        {
            "1.0.0": "2020-01-01T00:00:00+00:00",
            "2.0.0": "2020-06-01T00:00:00+00:00",
            "3.0.0": "2021-01-01T00:00:00+00:00",
        },
    )

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=2
    )

    assert outcome["removed"] == ["1.0.0"]
    assert set(outcome["kept"]) == {"2.0.0", "3.0.0"}
    assert not (plugin_root / "v1_0_0").exists()


def test_default_retention_window_keeps_the_previous_version(tmp_path: Path) -> None:
    """默认保留窗口留得下上一版，装错新版本后仍有一键切回的对象。"""
    plugin_root = tmp_path / "sample"
    for index, version in enumerate(("1.0.0", "2.0.0", "3.0.0")):
        _install_version(plugin_root, version)
        _stamp_installed_at(plugin_root, {version: f"2020-0{index + 1}-01T00:00:00+00:00"})

    outcome = recycle_plugin_version_directories(plugin_root, referenced_versions=set())

    assert PLUGIN_VERSION_RETENTION_WINDOW == 2
    assert outcome["removed"] == ["1.0.0"]
    assert (plugin_root / "v2_0_0").is_dir()


def test_missing_installed_at_is_treated_as_oldest(tmp_path: Path) -> None:
    """登记时间缺失的版本排到最旧，不占用保留窗口的名额。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")
    manifest = read_plugin_versions_manifest(plugin_root)
    for entry in manifest["versions"]:
        if entry["version"] == "1.0.0":
            entry.pop("installed_at", None)
    write_plugin_versions_manifest(plugin_root, manifest["versions"], manifest["current"])

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=1
    )

    assert outcome["removed"] == ["1.0.0"]
    assert set(outcome["kept"]) == {"2.0.0"}


def test_window_keeps_the_newest_when_every_installed_at_is_missing(
    tmp_path: Path,
) -> None:
    """登记时间全部缺失时保留窗口要保住最新的版本，而不是目录名字典序最靠前的。

    元信息丢失或损坏会让每个版本的登记时间都读成空串、排序键全相等；稳定排序不反转
    等值元素，窗口会退化成保留最旧的那几个，把当前正在加载的最新版本删掉。
    """
    plugin_root = tmp_path / "sample"
    for version in ("1.0.0", "1.1.0", "1.2.0"):
        _install_version(plugin_root, version)
    _stamp_installed_at(plugin_root, {"1.0.0": "", "1.1.0": "", "1.2.0": ""})

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=2
    )

    assert outcome["removed"] == ["1.0.0"]
    assert set(outcome["kept"]) == {"1.1.0", "1.2.0"}


def test_window_orders_by_semantic_version_not_lexicographic(tmp_path: Path) -> None:
    """登记时间并列时按版本号语义序兜底，1.10.0 排在 1.9.0 之后而不是之前。"""
    plugin_root = tmp_path / "sample"
    for version in ("1.9.0", "1.10.0"):
        _install_version(plugin_root, version)
    _stamp_installed_at(plugin_root, {"1.9.0": "", "1.10.0": ""})

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=1
    )

    assert outcome["removed"] == ["1.9.0"]
    assert (plugin_root / "v1_10_0").is_dir()


# 三、安装在途


def test_pending_installation_skips_recycle_entirely(tmp_path: Path) -> None:
    """未收尾安装事务存在时不动插件根目录下任何内容，元信息与源码逐字保持。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")
    before = {
        path.relative_to(plugin_root).as_posix(): path.read_bytes()
        for path in sorted(plugin_root.rglob("*"))
        if path.is_file()
    }

    outcome = recycle_plugin_version_directories(
        plugin_root,
        referenced_versions=set(),
        retention=0,
        has_pending_installation=True,
    )

    assert outcome["removed"] == []
    assert set(outcome["kept"]) == {"1.0.0", "2.0.0"}
    assert all(
        reason == PLUGIN_VERSION_KEPT_PENDING_INSTALL
        for reason in outcome["kept"].values()
    )
    after = {
        path.relative_to(plugin_root).as_posix(): path.read_bytes()
        for path in sorted(plugin_root.rglob("*"))
        if path.is_file()
    }
    assert after == before


# 四、孤儿版本目录


def test_orphan_version_dir_is_recycled_even_inside_the_window(tmp_path: Path) -> None:
    """元信息没登记的孤儿目录不占保留窗口，无引用即回收。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    orphan = _orphan_version_dir(plugin_root, "9.9.9")

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=PLUGIN_VERSION_RETENTION_WINDOW
    )

    assert outcome["removed"] == ["9.9.9"]
    assert not orphan.exists()
    assert (plugin_root / "v1_0_0").is_dir()


def test_orphan_version_dir_referenced_by_an_instance_is_kept(tmp_path: Path) -> None:
    """孤儿目录一旦被实例引用照样保留：引用判据优先于孤儿判据。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    orphan = _orphan_version_dir(plugin_root, "9.9.9")

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions={"9.9.9"}, retention=0
    )

    assert outcome["removed"] == []
    assert outcome["kept"]["9.9.9"] == PLUGIN_VERSION_KEPT_REFERENCED
    assert orphan.is_dir()


def test_unreadable_manifest_does_not_turn_every_version_into_an_orphan(
    tmp_path: Path,
) -> None:
    """元信息损坏时不做孤儿判定，否则「人人没登记」会把整个插件清空。"""
    plugin_root = tmp_path / "sample"
    for version in ("1.0.0", "2.0.0"):
        _install_version(plugin_root, version)
    (plugin_root / "versions.json").write_text("{ not json", encoding="utf-8")

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=2
    )

    assert outcome["removed"] == []
    assert (plugin_root / "v1_0_0").is_dir()
    assert (plugin_root / "v2_0_0").is_dir()


# 五、删除失败隔离与删除前的三重校验


def test_single_directory_delete_failure_does_not_block_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """单个版本目录删除失败只影响它自己，其余版本照常回收且元信息不摘除它。"""
    plugin_root = tmp_path / "sample"
    for version in ("1.0.0", "2.0.0", "3.0.0"):
        _install_version(plugin_root, version)
    original_rmtree = plugin_version_module.shutil.rmtree

    def flaky_rmtree(path, *args, **kwargs):
        """v1_0_0 的删除永远失败，其余目录按原样删除。"""
        if Path(path).name == "v1_0_0":
            raise OSError("boom")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(plugin_version_module.shutil, "rmtree", flaky_rmtree)

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    assert outcome["removed"] == ["2.0.0"]
    assert outcome["kept"]["1.0.0"] == PLUGIN_VERSION_KEPT_DELETE_FAILED
    assert (plugin_root / "v1_0_0").is_dir()
    manifest = read_plugin_versions_manifest(plugin_root)
    assert {entry["version"] for entry in manifest["versions"]} == {"1.0.0", "3.0.0"}


@pytest.mark.parametrize("name", ["dist", "wheels", "__pycache__"])
def test_delete_helper_refuses_reserved_directory_names(tmp_path: Path, name: str) -> None:
    """dist/wheels/__pycache__ 等保留条目反解不出版本号，删除请求被拒绝。"""
    plugin_root = tmp_path / "sample"
    entry = plugin_root / name
    entry.mkdir(parents=True)

    assert _delete_plugin_version_dir(plugin_root, name, entry) is False
    assert entry.is_dir()


def test_delete_helper_refuses_a_directory_name_mismatch(tmp_path: Path) -> None:
    """目录名反解出的版本号与待删除版本不一致时拒绝删除。"""
    plugin_root = tmp_path / "sample"
    version_dir = plugin_root / "v1_0_0"
    version_dir.mkdir(parents=True)

    assert _delete_plugin_version_dir(plugin_root, "2.0.0", version_dir) is False
    assert version_dir.is_dir()


def test_delete_helper_refuses_a_directory_outside_the_plugin_root(tmp_path: Path) -> None:
    """目录 resolve() 后位于插件目录之外时拒绝删除，不触发 rmtree。"""
    plugin_root = tmp_path / "sample"
    plugin_root.mkdir()
    outside = tmp_path / "v9_9_9"
    outside.mkdir()
    (outside / "marker.txt").write_text("keep", encoding="utf-8")

    assert _delete_plugin_version_dir(plugin_root, "9.9.9", outside) is False
    assert (outside / "marker.txt").exists()


def test_delete_helper_refuses_a_parent_traversal_path(tmp_path: Path) -> None:
    """拼接出的 .. 路径 resolve() 后落在插件目录之外，同样被包含性判断挡下。"""
    plugin_root = tmp_path / "sample"
    plugin_root.mkdir()
    sibling = tmp_path / "v9_9_9"
    sibling.mkdir()
    (sibling / "marker.txt").write_text("keep", encoding="utf-8")

    traversal = plugin_root / ".." / "v9_9_9"

    assert _delete_plugin_version_dir(plugin_root, "9.9.9", traversal) is False
    assert (sibling / "marker.txt").exists()


def test_delete_helper_refuses_the_plugin_root_itself(tmp_path: Path) -> None:
    """待删除目录就是插件目录本身时拒绝，即便名字碰巧能反解出版本号。"""
    plugin_root = tmp_path / "v1_0_0"
    plugin_root.mkdir()
    (plugin_root / "marker.txt").write_text("keep", encoding="utf-8")

    assert _delete_plugin_version_dir(plugin_root, "1.0.0", plugin_root) is False
    assert (plugin_root / "marker.txt").exists()


def test_recycle_refuses_a_symlink_pointing_outside_the_plugin_root(
    tmp_path: Path,
) -> None:
    """插件目录里指向外部的符号链接版本目录被挡下，链接目标不受损。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "marker.txt").write_text("keep", encoding="utf-8")
    (plugin_root / "v9_9_9").symlink_to(outside, target_is_directory=True)

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    assert "9.9.9" not in outcome["removed"]
    assert (outside / "marker.txt").exists()
    assert (plugin_root / "v9_9_9").is_symlink()


def test_recycle_refuses_a_symlink_aliasing_another_version_dir(tmp_path: Path) -> None:
    """指向同插件另一个版本目录的符号链接反解不回自身版本号，被挡下且不误删目标。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    (plugin_root / "v9_9_9").symlink_to(plugin_root / "v1_0_0", target_is_directory=True)

    outcome = recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    assert "9.9.9" not in outcome["removed"]
    assert (plugin_root / "v1_0_0" / "__init__.py").is_file()


def test_recycle_leaves_reserved_entries_alone(tmp_path: Path) -> None:
    """完整回收流程中，保留条目不会被当成版本目录考虑或删除。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")
    for reserved in ("dist", "wheels", "__pycache__"):
        (plugin_root / reserved).mkdir()

    recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    for reserved in ("dist", "wheels", "__pycache__"):
        assert (plugin_root / reserved).is_dir()


# 六、回收之后仍然加载得起来


def test_plugin_still_resolves_to_the_current_version_after_recycling(
    tmp_path: Path,
) -> None:
    """回收掉旧版本后当前版本照常解析得到，源码完好。"""
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")

    recycle_plugin_version_directories(
        plugin_root, referenced_versions=set(), retention=0
    )

    resolved = resolve_plugin_version_dir(plugin_root)
    assert resolved == plugin_root / "v2_0_0"
    assert (resolved / "__init__.py").read_text(encoding="utf-8").strip().endswith("'2.0.0'")


def test_a_binding_left_over_after_manual_deletion_falls_back_to_current(
    tmp_path: Path,
) -> None:
    """钉住的版本目录被手工删掉后，实例解析回落到当前版本而不是解析失败。

    回收本身不会制造这种残留——被钉住的版本一定在引用集合里、删不掉；这条用例守的是
    第五层「残留绑定自动收敛、无需额外处理」这个结论在加了回收之后依然成立。
    """
    plugin_root = tmp_path / "sample"
    _install_version(plugin_root, "1.0.0")
    _install_version(plugin_root, "2.0.0")
    pinned = PluginInstance(
        instance_id="SampleWork", source_plugin_id="sample", pinned_version="1.0.0"
    )
    plugin_version_module.shutil.rmtree(plugin_root / "v1_0_0")

    assert resolve_instance_version_dir(plugin_root, pinned) == plugin_root / "v2_0_0"


# 七、引用集合与并发拒绝（绑定服务层）


def _recycle_harness(tmp_path: Path, **kwargs) -> _Harness:
    """备好一个装了三个版本、登记时间递增的插件与其绑定服务脚手架。"""
    plugin_root = tmp_path / PLUGIN_ID.lower()
    for index, version in enumerate(("1.0.0", "2.0.0", "3.0.0")):
        _install_version(plugin_root, version)
        _stamp_installed_at(plugin_root, {version: f"2020-0{index + 1}-01T00:00:00+00:00"})
    return _Harness(plugins_root=tmp_path, **kwargs)


def test_pinned_version_of_a_disabled_clone_is_never_recycled(tmp_path: Path) -> None:
    """已停用分身钉住的版本同样进引用集合，回收不得删掉它。"""
    harness = _recycle_harness(
        tmp_path,
        clones={CLONE_ID: _clone("1.0.0", is_enabled=False)},
        hosts={PLUGIN_ID: _host()},
    )

    outcome = harness.service.recycle_versions(PLUGIN_ID, retention=0)

    assert outcome["removed"] == ["2.0.0"]
    assert outcome["kept"]["1.0.0"] == PLUGIN_VERSION_KEPT_REFERENCED
    assert (tmp_path / PLUGIN_ID.lower() / "v1_0_0").is_dir()


def test_a_following_instance_pins_down_the_current_version(tmp_path: Path) -> None:
    """没钉版的实例跟随当前版本，当前版本因而既是当前版本也被引用。"""
    harness = _recycle_harness(
        tmp_path,
        clones={CLONE_ID: _clone()},
        hosts={PLUGIN_ID: _host()},
    )

    referenced = harness.inventory.referenced_versions(PLUGIN_ID)

    assert referenced == {"3.0.0"}


def test_a_switch_not_yet_reloaded_protects_both_versions(tmp_path: Path) -> None:
    """绑定已落盘、重载尚未生效时，新旧两版都在引用集合里，一个都不许删。"""
    harness = _recycle_harness(
        tmp_path,
        clones={CLONE_ID: _clone("2.0.0")},
        hosts={PLUGIN_ID: _host()},
        # 内存里跑的还是切换前那一版
        running_versions={CLONE_ID: "1.0.0", PLUGIN_ID: "3.0.0"},
    )

    outcome = harness.service.recycle_versions(PLUGIN_ID, retention=0)

    assert outcome["removed"] == []
    assert outcome["kept"]["1.0.0"] == PLUGIN_VERSION_KEPT_REFERENCED
    assert outcome["kept"]["2.0.0"] == PLUGIN_VERSION_KEPT_REFERENCED
    assert outcome["kept"]["3.0.0"] == PLUGIN_VERSION_KEPT_CURRENT


def test_recycle_is_skipped_while_an_installation_is_in_flight(tmp_path: Path) -> None:
    """安装在途时整次回收跳过，一个版本目录都不删。"""
    harness = _recycle_harness(
        tmp_path,
        hosts={PLUGIN_ID: _host()},
        pending_installation=lambda _plugin_id: True,
    )

    outcome = harness.service.recycle_versions(PLUGIN_ID, retention=0)

    assert outcome["removed"] == []
    assert all(
        reason == PLUGIN_VERSION_KEPT_PENDING_INSTALL
        for reason in outcome["kept"].values()
    )
    assert (tmp_path / PLUGIN_ID.lower() / "v1_0_0").is_dir()


def test_recycle_refuses_when_the_installation_state_is_unknown(tmp_path: Path) -> None:
    """安装事务查询失败即判据未知，拒绝回收而不是按「没有在途」继续删除。"""

    def _explode(_plugin_id: str) -> bool:
        """模拟安装事务查询失败。"""
        raise ConnectionError("journal unavailable")

    harness = _recycle_harness(
        tmp_path,
        hosts={PLUGIN_ID: _host()},
        pending_installation=_explode,
    )

    with pytest.raises(RuntimeError, match="无法确认插件"):
        harness.service.recycle_versions(PLUGIN_ID, retention=0)

    assert (tmp_path / PLUGIN_ID.lower() / "v1_0_0").is_dir()


def test_reference_collection_failure_propagates_instead_of_deleting(
    tmp_path: Path,
) -> None:
    """实例读取失败时原样抛出，不得按空引用集合继续删除。"""

    def _explode(_source_plugin_id: str) -> list[PluginInstance]:
        """模拟实例表读取失败。"""
        raise ConnectionError("instance store unavailable")

    harness = _recycle_harness(tmp_path, hosts={PLUGIN_ID: _host()})
    harness.inventory._instances_for_source = _explode  # noqa: SLF001 - 注入读取失败

    with pytest.raises(ConnectionError):
        harness.service.recycle_versions(PLUGIN_ID, retention=0)

    assert (tmp_path / PLUGIN_ID.lower() / "v1_0_0").is_dir()


def test_recycle_rejects_an_unknown_plugin(tmp_path: Path) -> None:
    """插件不存在时拒绝回收，不去碰任何目录。"""
    harness = _recycle_harness(tmp_path, hosts={PLUGIN_ID: _host()})

    with pytest.raises(LookupError, match="不存在"):
        harness.service.recycle_versions("MissingPlugin")


def test_recycle_rejects_a_clone_instance_id(tmp_path: Path) -> None:
    """版本是源插件的属性，用分身自身的实例 ID 回收会被拒绝。"""
    harness = _recycle_harness(
        tmp_path,
        clones={CLONE_ID: _clone()},
        hosts={PLUGIN_ID: _host()},
        known_plugin_ids={PLUGIN_ID, CLONE_ID},
    )

    with pytest.raises(LookupError, match="是分身实例"):
        harness.service.recycle_versions(CLONE_ID)
