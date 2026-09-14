"""插件已装版本总览与实例版本绑定切换测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from app.runtime.extensions.plugin.binding import (
    PluginVersionBinding,
    PluginVersionInventory,
)
from app.runtime.extensions.plugin.version import (
    plugin_version_dir_name,
    write_plugin_versions_manifest,
)
from app.schemas.plugin import PluginInstance, PluginRuntimeStatus

PLUGIN_ID = "DemoPlugin"
CLONE_ID = "DemoPluginWork"


def _logger() -> SimpleNamespace:
    """提供绑定服务测试所需的最小日志端口。"""
    return SimpleNamespace(
        debug=lambda *_args: None,
        info=lambda *_args: None,
        warning=lambda *_args: None,
        error=lambda *_args: None,
    )


def _write_version_dir(plugins_root: Path, plugin_id: str, version: str) -> Path:
    """在插件根目录下创建一个空的版本目录。"""
    version_dir = plugins_root / plugin_id.lower() / plugin_version_dir_name(version)
    version_dir.mkdir(parents=True)
    return version_dir


def _write_manifest(
    plugin_root: Path, versions: list[str], current: str | None
) -> None:
    """写入版本元信息文件，登记时间固定以消除真实时钟带来的不确定性。"""
    write_plugin_versions_manifest(
        plugin_root,
        [
            {
                "version": version,
                "directory": plugin_version_dir_name(version),
                "installed_at": f"2026-01-0{index + 1}T00:00:00+00:00",
                "source": "market",
            }
            for index, version in enumerate(versions)
        ],
        current,
    )


def _installed(tmp_path: Path, versions: list[str], current: str | None) -> Path:
    """备好一个装有若干版本目录并登记了当前版本的插件。"""
    for version in versions:
        _write_version_dir(tmp_path, PLUGIN_ID, version)
    plugin_root = tmp_path / PLUGIN_ID.lower()
    _write_manifest(plugin_root, versions, current)
    return plugin_root


class _Harness:
    """组装版本绑定依赖并记录调用轨迹的测试脚手架。

    运行表是可变的：``stop`` 摘掉运行对象，``start`` 在状态为 ACTIVE 时按本次实际
    生效的版本重新放进去。版本切换的补偿链全靠「切换前实际跑的是哪一版」驱动，静态
    快照会让回退分支永远走不到。
    """

    def __init__(
        self,
        *,
        plugins_root: Path,
        clones: dict[str, PluginInstance] | None = None,
        hosts: dict[str, PluginInstance] | None = None,
        known_plugin_ids: set[str] | None = None,
        running_versions: dict[str, str] | None = None,
        start_results: dict[str | None, PluginRuntimeStatus] | None = None,
        effective_versions: dict[str | None, str | None] | None = None,
        stop_results: list[bool] | None = None,
        blockers: list[str] | None = None,
        display_names: dict[str, str] | None = None,
        refresh_registrations=None,
        pending_installation=None,
        save_error: Exception | None = None,
    ) -> None:
        """按用例需要装配读取端口、生命周期端口与安装事务查询端口。"""
        self.clones: dict[str, PluginInstance] = dict(clones or {})
        self.hosts: dict[str, PluginInstance] = dict(hosts or {})
        self.saved: list[PluginInstance] = []
        self.saved_hosts: list[PluginInstance] = []
        self.stopped: list[str] = []
        self.start_calls: list[tuple[str, str | None]] = []
        self.blocker_calls: list[tuple[str, list[Path]]] = []
        self.refreshed: list[str] = []
        self.running: dict[str, str | None] = dict(running_versions or {})
        self._known_plugin_ids = (
            {PLUGIN_ID} if known_plugin_ids is None else known_plugin_ids
        )
        self._start_results = start_results or {}
        self._effective_versions = effective_versions or {}
        self._stop_results = list(stop_results or [])
        self._blockers = list(blockers or [])
        self._save_error = save_error
        self.logger = _logger()
        self.inventory = PluginVersionInventory(
            plugins_root=plugins_root,
            plugin_exists=lambda plugin_id: plugin_id in self._known_plugin_ids,
            get_instance=self.clones.get,
            instances_for_source=self._clones_for_source,
            get_host_instance=self.hosts.get,
            running=lambda: {
                instance_id: SimpleNamespace(plugin_version=version)
                for instance_id, version in self.running.items()
            },
            display_name=(display_names or {}).get,
        )
        self.service = PluginVersionBinding(
            inventory=self.inventory,
            save_instance=self._save_instance,
            save_host_instance=self._save_host_instance,
            start=self._start,
            stop=self._stop,
            log=self.logger,
            multi_version_blockers=self._multi_version_blockers,
            refresh_registrations=refresh_registrations or self.refreshed.append,
            pending_installation=pending_installation,
        )

    def _clones_for_source(self, source_plugin_id: str) -> list[PluginInstance]:
        """列出引用同一源码的分身。"""
        return [
            clone
            for clone in self.clones.values()
            if clone.source_plugin_id == source_plugin_id
        ]

    def _save_instance(self, instance: PluginInstance) -> None:
        """记录分身绑定写入。"""
        if self._save_error is not None:
            raise self._save_error
        self.clones[instance.instance_id] = instance
        self.saved.append(instance)

    def _save_host_instance(self, instance: PluginInstance) -> None:
        """记录本体绑定写入。"""
        if self._save_error is not None:
            raise self._save_error
        self.hosts[instance.instance_id] = instance
        self.saved_hosts.append(instance)

    def _stop(self, instance_id: str) -> bool:
        """摘掉运行对象并按预设脚本返回本次停止结果。"""
        self.stopped.append(instance_id)
        result = self._stop_results.pop(0) if self._stop_results else True
        if result:
            self.running.pop(instance_id, None)
        return result

    def _start(self, instance_id: str, version: str | None) -> dict:
        """按预设脚本给出启动结果，并把实际生效的版本放回运行表。"""
        self.start_calls.append((instance_id, version))
        status = self._start_results.get(version, PluginRuntimeStatus.ACTIVE)
        if status == PluginRuntimeStatus.ACTIVE:
            self.running[instance_id] = self._effective_versions.get(version, version)
        return {instance_id: status}

    def _multi_version_blockers(self, plugin_id: str, source_dirs: list[Path]) -> list[str]:
        """记录体检调用并返回预设的阻断原因。"""
        self.blocker_calls.append((plugin_id, list(source_dirs)))
        return list(self._blockers)


def _clone(pinned: str | None = None, **overrides) -> PluginInstance:
    """构造一个引用 DemoPlugin 源码的分身描述。"""
    return PluginInstance(
        instance_id=CLONE_ID,
        source_plugin_id=PLUGIN_ID,
        pinned_version=pinned,
        **overrides,
    )


def _host(pinned: str | None = None, **overrides) -> PluginInstance:
    """构造 DemoPlugin 本体自身那一行。"""
    return PluginInstance(
        instance_id=PLUGIN_ID,
        source_plugin_id=PLUGIN_ID,
        pinned_version=pinned,
        **overrides,
    )


# 一、已装版本总览


def test_overview_lists_installed_versions_and_instance_bindings(tmp_path: Path):
    """总览含已装版本落盘信息、本体与分身各自的绑定与运行状态。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone("1.0.0")},
        hosts={PLUGIN_ID: _host()},
        running_versions={PLUGIN_ID: "2.0.0", CLONE_ID: "1.0.0"},
        display_names={CLONE_ID: "工作用分身"},
    )

    overview = harness.service.overview(PLUGIN_ID)

    assert overview["plugin_id"] == PLUGIN_ID
    assert overview["current_version"] == "2.0.0"
    assert overview["installed_versions"] == [
        {
            "version": "1.0.0",
            "directory": "v1_0_0",
            "installed_at": "2026-01-01T00:00:00+00:00",
            "source": "market",
            "is_current": False,
        },
        {
            "version": "2.0.0",
            "directory": "v2_0_0",
            "installed_at": "2026-01-02T00:00:00+00:00",
            "source": "market",
            "is_current": True,
        },
    ]
    host_view, clone_view = overview["instances"]
    assert host_view["instance_id"] == PLUGIN_ID and host_view["is_host"] is True
    assert host_view["pinned_version"] is None
    assert host_view["running"] is True and host_view["running_version"] == "2.0.0"
    assert clone_view["instance_id"] == CLONE_ID and clone_view["is_host"] is False
    assert clone_view["pinned_version"] == "1.0.0"
    assert clone_view["plugin_name"] == "工作用分身"


def test_overview_sorts_versions_semantically_not_lexicographically(tmp_path: Path):
    """1.10.0 排在 1.9.0 之后：字典序会把两者颠倒，与声明的升序口径不符。"""
    _installed(tmp_path, ["1.9.0", "1.10.0"], current="1.10.0")
    harness = _Harness(plugins_root=tmp_path)

    overview = harness.service.overview(PLUGIN_ID)

    assert [item["version"] for item in overview["installed_versions"]] == [
        "1.9.0",
        "1.10.0",
    ]


def test_overview_shows_an_unbound_host_as_following_current(tmp_path: Path):
    """本体从未登记过任何设置时也要出现在列表里，按跟随当前版本呈现。"""
    _installed(tmp_path, ["1.0.0"], current="1.0.0")
    harness = _Harness(plugins_root=tmp_path)

    overview = harness.service.overview(PLUGIN_ID)

    assert len(overview["instances"]) == 1
    assert overview["instances"][0] == {
        "instance_id": PLUGIN_ID,
        "plugin_name": None,
        "pinned_version": None,
        "running": False,
        "running_version": None,
        "is_host": True,
        "is_default_target": False,
        "is_enabled": True,
    }


def test_overview_falls_back_to_the_persisted_name_when_a_clone_is_not_loaded(tmp_path: Path):
    """加载失败的分身取不到运行态类名，回落到描述符里持久化的名称而不是裸 ID。"""
    _installed(tmp_path, ["1.0.0"], current="1.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone(plugin_name="上次登记的名字")},
    )

    overview = harness.service.overview(PLUGIN_ID)

    assert overview["instances"][1]["plugin_name"] == "上次登记的名字"
    assert overview["instances"][1]["running"] is False


def test_overview_lists_a_disabled_clone_with_the_switch_off(tmp_path: Path):
    """停用的分身仍在册，要列得出来，只是启用位是关的。"""
    _installed(tmp_path, ["1.0.0"], current="1.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone(is_enabled=False)},
    )

    overview = harness.service.overview(PLUGIN_ID)

    assert overview["instances"][1]["is_enabled"] is False
    assert overview["instances"][1]["running"] is False


def test_overview_raises_lookup_error_for_unknown_plugin(tmp_path: Path):
    """插件不存在时抛 LookupError，由接口层转成可读失败响应。"""
    harness = _Harness(plugins_root=tmp_path, known_plugin_ids=set())

    try:
        harness.service.overview("Missing")
    except LookupError as error:
        assert "不存在" in str(error)
    else:
        raise AssertionError("插件不存在时必须抛出 LookupError")


def test_overview_rejects_a_clone_own_id_as_plugin_id(tmp_path: Path):
    """拿分身自身的实例 ID 查版本总览要被明确拒绝，而不是当成一个空插件。"""
    _installed(tmp_path, ["1.0.0"], current="1.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        known_plugin_ids={PLUGIN_ID, CLONE_ID},
    )

    try:
        harness.service.overview(CLONE_ID)
    except LookupError as error:
        assert "分身实例" in str(error)
    else:
        raise AssertionError("用分身 ID 查版本总览时必须抛出 LookupError")


# 二、钉版与解除钉版


def test_set_instance_version_pins_a_clone_and_restarts_it(tmp_path: Path):
    """钉版成功：绑定先落盘，随后完整走一次停止再启动，并刷新宿主注册。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert (success, message) == (True, CLONE_ID)
    assert harness.clones[CLONE_ID].pinned_version == "1.0.0"
    assert harness.stopped == [CLONE_ID]
    assert harness.start_calls == [(CLONE_ID, "1.0.0")]
    assert harness.refreshed == [CLONE_ID]


def test_set_instance_version_unpins_back_to_following_current(tmp_path: Path):
    """解除钉版把绑定写回空，并按当前版本重新起来。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone("1.0.0")},
        running_versions={CLONE_ID: "1.0.0"},
        effective_versions={None: "2.0.0"},
    )

    success, _message = harness.service.set_instance_version(CLONE_ID)

    assert success is True
    assert harness.clones[CLONE_ID].pinned_version is None
    # 启动不传版本号：由加载器按绑定记录解析当前版本，而不是把一个算出来的版本硬塞进去
    assert harness.start_calls == [(CLONE_ID, None)]
    assert harness.running[CLONE_ID] == "2.0.0"


def test_set_instance_version_treats_blank_as_unpin(tmp_path: Path):
    """空白串与不传等价：前端清空输入框表达的就是「改为跟随当前版本」。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone("1.0.0")},
        running_versions={CLONE_ID: "1.0.0"},
        effective_versions={None: "2.0.0"},
    )

    success, _message = harness.service.set_instance_version(CLONE_ID, pinned_version="  ")

    assert success is True
    assert harness.clones[CLONE_ID].pinned_version is None
    assert harness.start_calls == [(CLONE_ID, None)]


def test_set_instance_version_applies_to_the_source_plugin_host(tmp_path: Path):
    """本体与分身共用一个入口：传插件 ID 时写的是本体那一行，不是新建一个分身。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        running_versions={PLUGIN_ID: "2.0.0"},
    )

    success, _message = harness.service.set_instance_version(
        PLUGIN_ID, pinned_version="1.0.0"
    )

    assert success is True
    assert harness.saved == []
    assert harness.hosts[PLUGIN_ID].pinned_version == "1.0.0"
    assert harness.hosts[PLUGIN_ID].is_host is True


def test_set_instance_version_updates_an_existing_host_binding(tmp_path: Path):
    """本体已有绑定时就地改写，不覆盖它承载的其它设置。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        hosts={PLUGIN_ID: _host("1.0.0", plugin_name="本体展示名", is_default_target=True)},
        running_versions={PLUGIN_ID: "1.0.0"},
    )

    success, _message = harness.service.set_instance_version(
        PLUGIN_ID, pinned_version="2.0.0"
    )

    assert success is True
    assert harness.hosts[PLUGIN_ID].pinned_version == "2.0.0"
    assert harness.hosts[PLUGIN_ID].plugin_name == "本体展示名"
    assert harness.hosts[PLUGIN_ID].is_default_target is True


# 三、切换前的拒绝判据


def test_set_instance_version_rejects_an_uninstalled_target(tmp_path: Path):
    """目标版本没装就拒绝，绑定与运行态一律不动。"""
    _installed(tmp_path, ["1.0.0"], current="1.0.0")
    harness = _Harness(plugins_root=tmp_path, clones={CLONE_ID: _clone()})

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="9.9.9"
    )

    assert success is False
    assert "未安装版本 9.9.9" in message
    assert harness.saved == [] and harness.stopped == [] and harness.start_calls == []


def test_set_instance_version_returns_failure_for_unknown_instance(tmp_path: Path):
    """既不是已知分身也不是已知插件本体时直接报不存在。"""
    harness = _Harness(plugins_root=tmp_path, known_plugin_ids=set())

    success, message = harness.service.set_instance_version("Ghost", pinned_version="1.0.0")

    assert success is False
    assert "不存在" in message


def test_set_instance_version_rejects_while_a_package_write_is_in_flight(tmp_path: Path):
    """安装在途时磁盘内容正在变，切过去可能落到写了一半的源码上，必须拒绝。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        pending_installation=lambda _plugin_id: True,
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "正在安装或写入" in message
    assert harness.saved == [] and harness.stopped == []


def test_set_instance_version_fails_closed_when_the_install_state_is_unknown(tmp_path: Path):
    """安装事务查询本身抛出时按未知处理并拒绝，而不是当成没有安装在途。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")

    def _explode(_plugin_id: str) -> bool:
        """模拟安装事务查询故障。"""
        raise RuntimeError("journal 不可读")

    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        pending_installation=_explode,
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "无法确认" in message
    assert harness.stopped == []


def test_set_instance_version_rejects_when_coexistence_is_unsupported(tmp_path: Path):
    """本次切换会造成多版本并存、而写法不支持并存时拒绝，且什么都不动。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        hosts={PLUGIN_ID: _host()},
        blockers=["自引用绝对导入"],
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "不支持多版本并存" in message and "自引用绝对导入" in message
    assert harness.saved == [] and harness.stopped == []
    assert harness.blocker_calls and harness.blocker_calls[0][0] == PLUGIN_ID.lower()


def test_set_instance_version_allows_coexistence_when_no_blockers_are_found(tmp_path: Path):
    """确实会并存但写法合规时照常切换。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        hosts={PLUGIN_ID: _host()},
        running_versions={CLONE_ID: "2.0.0"},
    )

    success, _message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is True
    assert harness.blocker_calls != []


def test_set_instance_version_skips_the_scan_when_no_coexistence_arises(tmp_path: Path):
    """插件只有这一个实例时切哪一版都不会并存，不必为它扫描全部源码。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        running_versions={PLUGIN_ID: "2.0.0"},
        blockers=["自引用绝对导入"],
    )

    success, _message = harness.service.set_instance_version(
        PLUGIN_ID, pinned_version="1.0.0"
    )

    assert success is True
    assert harness.blocker_calls == []


def test_set_instance_version_guards_the_switch_back_to_following_current(tmp_path: Path):
    """改为跟随当前版本同样可能制造并存，不能绕过守卫。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone("1.0.0")},
        hosts={PLUGIN_ID: _host("1.0.0")},
        blockers=["宿主共享声明基类建模"],
    )

    success, message = harness.service.set_instance_version(CLONE_ID)

    assert success is False
    assert "不支持多版本并存" in message


def test_coexistence_uses_the_hosts_actual_pinned_version_not_the_manifest_current(
    tmp_path: Path,
):
    """本体被钉在旧版本时不能假设它在跑当前版本：分身切到同一版其实不会并存。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        hosts={PLUGIN_ID: _host("1.0.0")},
        blockers=["自引用绝对导入"],
        running_versions={CLONE_ID: "2.0.0"},
    )

    success, _message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is True
    assert harness.blocker_calls == []


# 四、切换失败与补偿


def test_set_instance_version_does_not_start_when_stop_reports_failure(tmp_path: Path):
    """旧实例没停干净就不许起新的，绑定原样恢复。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
        stop_results=[False],
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "停止旧实例失败" in message
    assert harness.start_calls == []
    assert harness.clones[CLONE_ID].pinned_version is None


def test_set_instance_version_restores_the_binding_when_the_switch_fails(tmp_path: Path):
    """目标版本起不来且没有可回退的运行版本时，绑定恢复成切换前的样子。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        start_results={"1.0.0": PluginRuntimeStatus.LOAD_FAILED},
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "请查看插件日志" in message
    assert harness.clones[CLONE_ID].pinned_version is None
    assert harness.refreshed == [CLONE_ID]


def test_set_instance_version_falls_back_to_the_previous_effective_version(tmp_path: Path):
    """目标版本起不来时以切换前实际运行的版本重启，并恢复原来的绑定语义。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
        start_results={"1.0.0": PluginRuntimeStatus.LOAD_FAILED},
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "已回退到原版本 2.0.0" in message
    assert harness.start_calls == [(CLONE_ID, "1.0.0"), (CLONE_ID, "2.0.0")]
    # 回退期间临时钉住旧版本，回退起来之后才恢复成切换前的「跟随当前版本」
    assert [saved.pinned_version for saved in harness.saved] == ["1.0.0", "2.0.0", None]
    assert harness.clones[CLONE_ID].pinned_version is None


def test_set_instance_version_reports_failure_when_the_fallback_also_fails(tmp_path: Path):
    """目标与回退都起不来时如实报告，并撤销仍指向旧实例的宿主注册。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
        start_results={
            "1.0.0": PluginRuntimeStatus.LOAD_FAILED,
            "2.0.0": PluginRuntimeStatus.LOAD_FAILED,
        },
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "回退到原版本 2.0.0 同样失败" in message
    assert harness.clones[CLONE_ID].pinned_version is None
    assert harness.refreshed == [CLONE_ID]


def test_set_instance_version_detects_a_silent_fallback_to_the_current_version(
    tmp_path: Path,
):
    """加载器回落到当前版本却仍报 ACTIVE 时不能算切换成功，要清掉并回退。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
        # 请求 1.0.0，实际生效的却是 2.0.0
        effective_versions={"1.0.0": "2.0.0"},
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "已回退到原版本 2.0.0" in message
    assert harness.clones[CLONE_ID].pinned_version is None


def test_set_instance_version_reports_a_failed_binding_write(tmp_path: Path):
    """绑定写不进去就不进入停启流程，避免停了却没有落盘的绑定可依。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")
    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        save_error=RuntimeError("数据库不可写"),
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "保存插件实例" in message
    assert harness.stopped == [] and harness.start_calls == []


def test_set_instance_version_reports_a_failed_registration_refresh(tmp_path: Path):
    """切换本身成功但注册刷新失败时如实报告，并带上实际运行的版本。"""
    _installed(tmp_path, ["1.0.0", "2.0.0"], current="2.0.0")

    def _explode(_instance_id: str) -> None:
        """模拟动态路由刷新故障。"""
        raise RuntimeError("动态路由注册失败")

    harness = _Harness(
        plugins_root=tmp_path,
        clones={CLONE_ID: _clone()},
        running_versions={CLONE_ID: "2.0.0"},
        refresh_registrations=_explode,
    )

    success, message = harness.service.set_instance_version(
        CLONE_ID, pinned_version="1.0.0"
    )

    assert success is False
    assert "注册刷新失败" in message and "1.0.0" in message
    assert harness.clones[CLONE_ID].pinned_version == "1.0.0"
