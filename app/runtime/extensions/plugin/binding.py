"""插件已装版本事实读取与实例级版本绑定切换。

本模块刻意分成两个类：``PluginVersionInventory`` 只回答「现在是什么样」——装了哪些
版本、每个实例绑定到哪一版、此刻实际跑的是哪一版；``PluginVersionBinding`` 才执行
「改成什么样」的状态迁移，连同它那条失败必须逐步补偿的回退链。两者混在一个类里时，
只读的总览查询与带补偿的停启事务共用一份实例状态，读路径的任何改动都要重新论证它
会不会影响正在补偿中的切换。
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Optional

from app.runtime.extensions.plugin.readiness import plugin_multi_version_blockers
from app.runtime.extensions.plugin.version import (
    PLUGIN_VERSION_RETENTION_WINDOW,
    compare_plugin_versions,
    plugin_version_dirs,
    read_plugin_versions_manifest,
    recycle_plugin_version_directories,
)
from app.schemas.plugin import PluginInstance, PluginRuntimeStatus

StartInstance = Callable[[str, Optional[str]], dict[str, PluginRuntimeStatus]]
StopInstance = Callable[[str], Optional[bool]]
MultiVersionBlockers = Callable[[str, list[Path]], list[str]]
RefreshRegistrations = Callable[[str], None]
PendingInstallation = Callable[[str], bool]


def _ignore_registration_refresh(_instance_id: str) -> None:
    """宿主尚未装配注册刷新端口时保持版本切换可用。"""


def _no_display_name(_instance_id: str) -> Optional[str]:
    """宿主尚未装配名称解析端口时回落到实例自身登记的名称。"""
    return None


def _never_pending(_plugin_id: str) -> bool:
    """宿主尚未装配安装事务查询端口时按「没有安装在途」处理。

    端口缺席与「查得到但结果未知」是两回事：前者说明这套接线根本没有安装流程可言
    （单元测试、裸运行时），按在途处理会让版本切换永远打不开；后者是真正的未知状态，
    由 ``set_instance_version`` 失败关闭。
    """
    return False


class PluginVersionInventory:
    """只读地回答插件的版本事实：装了哪些版本、谁绑定到哪一版、此刻在跑哪一版。

    绑定是一条独立于磁盘的事实：磁盘只说得出「装了哪些版本」，说不出「这个实例要用
    哪一个」。因此本类从不由磁盘推导绑定，磁盘只在两处参与判定——枚举已装版本，以及
    「跟随当前版本」究竟落到哪一版。
    """

    def __init__(
        self,
        *,
        plugins_root: Path,
        plugin_exists: Callable[[str], bool],
        get_instance: Callable[[str], Optional[PluginInstance]],
        instances_for_source: Callable[[str], list[PluginInstance]],
        get_host_instance: Callable[[str], Optional[PluginInstance]],
        running: Callable[[], dict[str, Any]],
        display_name: Callable[[str], Optional[str]] | None = None,
    ) -> None:
        """保存版本目录根、实例读取端口与运行表快照端口。"""
        self._plugins_root = plugins_root
        self._plugin_exists = plugin_exists
        self._get_instance = get_instance
        self._instances_for_source = instances_for_source
        self._get_host_instance = get_host_instance
        self._running = running
        self._display_name = display_name or _no_display_name

    def plugin_exists(self, plugin_id: str) -> bool:
        """判断该插件是否存在。"""
        return self._plugin_exists(plugin_id)

    def clone_instance(self, instance_id: str) -> Optional[PluginInstance]:
        """按实例 ID 读取分身描述；本体自身那一行不会从这里返回。"""
        return self._get_instance(instance_id)

    def clones_for_source(self, plugin_id: str) -> list[PluginInstance]:
        """列出共享该源码的全部分身，不含本体自身那一行。"""
        return self._instances_for_source(plugin_id)

    def plugin_root(self, plugin_id: str) -> Path:
        """定位插件源码根目录。"""
        return self._plugins_root / plugin_id.lower()

    def installed_versions(self, plugin_id: str) -> dict[str, Path]:
        """枚举磁盘上的已装版本目录。"""
        return plugin_version_dirs(self.plugin_root(plugin_id))

    def current_version(self, plugin_id: str) -> Optional[str]:
        """读取版本元信息登记的当前版本号。"""
        manifest = read_plugin_versions_manifest(self.plugin_root(plugin_id))
        current = manifest.get("current")
        return current if isinstance(current, str) and current else None

    @staticmethod
    def _default_host_instance(plugin_id: str) -> PluginInstance:
        """本体从未被显式绑定过版本时的默认视图：跟随当前版本。"""
        return PluginInstance(instance_id=plugin_id, source_plugin_id=plugin_id)

    def host_instance(self, plugin_id: str) -> PluginInstance:
        """读取源插件本体的版本绑定，从未登记过时给出跟随当前版本的默认视图。"""
        return self._get_host_instance(plugin_id) or self._default_host_instance(plugin_id)

    def running_instance(self, instance_id: str) -> Any | None:
        """按实例 ID 读取当前运行对象，兼容大小写不同的注册表键。"""
        running = self._running()
        instance = running.get(instance_id)
        if instance is not None:
            return instance
        target = instance_id.casefold()
        return next(
            (value for key, value in running.items() if key.casefold() == target),
            None,
        )

    def running_version(self, instance_id: str) -> Optional[str]:
        """读取实例当前运行对象实际加载的版本，未运行或无版本声明时为空。"""
        running = self.running_instance(instance_id)
        version = getattr(running, "plugin_version", None) if running is not None else None
        return version if isinstance(version, str) and version else None

    @staticmethod
    def expected_version(
        instance: PluginInstance,
        current_version: Optional[str],
    ) -> Optional[str]:
        """解析实例按其绑定本应运行的版本：钉住即钉住那版，否则即当前版本。"""
        return instance.pinned_version or current_version

    def referenced_versions(self, plugin_id: str) -> set[str]:
        """收集该插件下任何实例仍在引用的版本号，供版本回收判定「谁还用得着」。

        每个实例贡献两个版本号，缺一不可：按绑定解析出的**期望版本**（钉住即那一版，
        没钉版即当前版本），以及此刻**实际加载**中的版本。一次刚把绑定落盘、重载却
        还没生效的切换里这两者正好不同——期望版本是要切过去的新版本，内存里跑的仍是
        旧版本，只记其中一个必然把另一半删掉：删新版本会让重载落空，删旧版本则会把
        一个正在服务请求的实例的源码从脚下抽走。

        本体与全部分身一视同仁，且分身不按启用位过滤：停用的分身随时可能被重新启用，
        把它钉住的版本当成无人引用删掉，等于让它再也起不来。

        集合来自对实例存储与运行表的实测查询；任何读取失败都原样向上抛出，由回收调用方
        跳过本次回收，而不是在这里退化成空集——凑不齐引用集合时按空集继续就是把「不知道
        谁在用」当成「没人在用」，那正是误删正在跑的版本的唯一路径。

        :param plugin_id: 源插件ID
        :return: 被引用的版本号集合
        """
        current_version = self.current_version(plugin_id)
        referenced: set[str] = set()
        for instance in (self.host_instance(plugin_id), *self.clones_for_source(plugin_id)):
            expected = self.expected_version(instance, current_version)
            if expected:
                referenced.add(expected)
            running = self.running_version(instance.instance_id)
            if running:
                referenced.add(running)
        return referenced

    def resolve_target_version(
        self,
        plugin_id: str,
        requested_version: Optional[str],
    ) -> Optional[str]:
        """解析一次切换实际期望运行的版本号。

        显式指定时必须确实已安装，否则返回 None 交由调用方拒绝；改为跟随当前版本时
        取清单登记的当前版本，清单缺失则取磁盘上语义最高的已装版本——与加载解析的
        回落口径一致，否则并存判定会拿一个加载器根本不会用的版本去比。

        :param plugin_id: 源插件ID
        :param requested_version: 请求锚定的版本号，为空表示改为跟随当前版本
        :return: 目标版本号；请求的版本未安装、或插件尚无任何已装版本时为 None
        """
        installed = self.installed_versions(plugin_id)
        if requested_version is not None:
            return requested_version if requested_version in installed else None
        current = self.current_version(plugin_id)
        if current is not None:
            return current
        if not installed:
            return None
        return max(installed, key=cmp_to_key(compare_plugin_versions))

    def creates_version_coexistence(
        self,
        instance: PluginInstance,
        target_version: str,
    ) -> bool:
        """判断把指定实例切到目标版本后，该插件是否会出现多版本同时在跑。

        本体的期望版本同样并入候选集合：本体从未被显式绑定过版本时按跟随当前版本的
        默认视图解析，本体已被钉住某个版本时改按该绑定解析，不想当然地假设本体始终
        运行当前版本。被切换的正是本体自身时跳过这一项——切换后本体将处于
        ``target_version``，计入切换前的期望版本等于拿自己和自己比出一次假并存。
        """
        current_version = self.current_version(instance.source_plugin_id)
        versions: set[str] = set()
        if not instance.is_host:
            host_expected = self.expected_version(
                self.host_instance(instance.source_plugin_id), current_version
            )
            if host_expected:
                versions.add(host_expected)
        for sibling in self.clones_for_source(instance.source_plugin_id):
            if sibling.instance_id == instance.instance_id:
                continue
            sibling_version = self.expected_version(sibling, current_version)
            if sibling_version:
                versions.add(sibling_version)
        versions.add(target_version)
        return len(versions) > 1

    def overview(self, plugin_id: str) -> dict[str, Any]:
        """组装插件已装版本列表，以及本体与各分身实例的版本绑定。

        实例列表首项固定是本体自身的版本绑定，其余是共享该源码的各个分身；每项都带
        ``is_host`` 标记二者身份。本体从未被显式绑定过版本时按跟随当前版本的默认视图
        呈现，而不是从列表中略去——本体始终是一个可以被钉版的对象，把它藏起来会让
        「这个插件本身跑的是哪一版」既无从表达也无从修改。

        :param plugin_id: 插件ID
        :return: 含已装版本列表与本体、各分身绑定信息的字典
        :raise LookupError: 插件不存在，或 ``plugin_id`` 实为某个分身自身的实例 ID
        """
        if not self._plugin_exists(plugin_id):
            raise LookupError(f"插件 {plugin_id} 不存在")
        if self._get_instance(plugin_id) is not None:
            raise LookupError(f"{plugin_id} 是分身实例，请使用源插件 ID 查询版本与实例")
        manifest = read_plugin_versions_manifest(self.plugin_root(plugin_id))
        current_version = self.current_version(plugin_id)
        registered = {
            entry.get("version"): entry
            for entry in (manifest.get("versions") or [])
            if isinstance(entry, dict)
        }
        installed_versions = [
            {
                "version": version,
                "directory": path.name,
                "installed_at": (registered.get(version) or {}).get("installed_at"),
                "source": (registered.get(version) or {}).get("source"),
                "is_current": version == current_version,
            }
            # 按版本号语义排序：字典序会把 1.10.0 排在 1.9.0 前面，与响应模型声明的
            # 「按版本号升序」以及加载解析当前版本时用的比较口径都对不上
            for version, path in sorted(
                self.installed_versions(plugin_id).items(),
                key=lambda item: cmp_to_key(compare_plugin_versions)(item[0]),
            )
        ]
        instances = [
            self._binding_view(self.host_instance(plugin_id)),
            *(self._binding_view(clone) for clone in self.clones_for_source(plugin_id)),
        ]
        return {
            "plugin_id": plugin_id,
            "current_version": current_version,
            "installed_versions": installed_versions,
            "instances": instances,
        }

    def _binding_view(self, instance: PluginInstance) -> dict[str, Any]:
        """把持久化绑定与运行中实例的实际版本合并为接口投影。"""
        return {
            "instance_id": instance.instance_id,
            # 优先取运行态注册的展示名：分身的名称在加载时才被写进类上，本体的名称
            # 则只存在于插件类、实例描述符里根本没有。加载失败的分身取不到类，回落到
            # 描述符里持久化的名称，而不是退成一行裸 ID
            "plugin_name": self._display_name(instance.instance_id) or instance.plugin_name,
            "pinned_version": instance.pinned_version,
            "running": self.running_instance(instance.instance_id) is not None,
            "running_version": self.running_version(instance.instance_id),
            "is_host": instance.is_host,
            "is_default_target": instance.is_default_target,
            # 与 running 是两回事：这里说的是「该不该被实例化」，running 说的是
            # 「此刻在不在跑」。停用的实例仍要出现在列表里，只是开关是关的
            "is_enabled": instance.is_enabled,
        }


class PluginVersionBinding:
    """执行实例级版本绑定切换，并在每一步失败时逐级补偿。"""

    def __init__(
        self,
        *,
        inventory: PluginVersionInventory,
        save_instance: Callable[[PluginInstance], None],
        save_host_instance: Callable[[PluginInstance], None],
        start: StartInstance,
        stop: StopInstance,
        log: Any,
        multi_version_blockers: MultiVersionBlockers = plugin_multi_version_blockers,
        refresh_registrations: RefreshRegistrations | None = None,
        pending_installation: PendingInstallation | None = None,
    ) -> None:
        """保存版本事实读取口、实例持久化、生命周期与安装事务查询端口。"""
        self._inventory = inventory
        self._save_instance = save_instance
        self._save_host_instance = save_host_instance
        self._start = start
        self._stop = stop
        self._logger = log
        self._multi_version_blockers = multi_version_blockers
        self._refresh_registrations = refresh_registrations or _ignore_registration_refresh
        self._pending_installation = pending_installation or _never_pending

    def overview(self, plugin_id: str) -> dict[str, Any]:
        """转交版本总览查询，让管理面只依赖一个版本门面。

        :param plugin_id: 插件ID
        :return: 含已装版本列表与各实例绑定信息的字典
        :raise LookupError: 插件不存在，或 ``plugin_id`` 实为某个分身自身的实例 ID
        """
        return self._inventory.overview(plugin_id)

    def recycle_versions(
        self,
        plugin_id: str,
        retention: int = PLUGIN_VERSION_RETENTION_WINDOW,
    ) -> dict[str, Any]:
        """回收该插件不再被任何实例引用、也不在保留窗口内的已装版本目录。

        引用集合先于安装事务查询算出：它读的是实例表与运行表，不碰磁盘，先算不会
        让在途安装的窗口白白延长。安装事务查询失败一律向上抛出而不是按「没有在途」
        继续——那道判据存在的意义正是拦住「磁盘内容正在变」的时刻，把未知当成安全
        等于把它取消掉。

        :param plugin_id: 源插件ID
        :param retention: 额外按登记时间保留的最近版本数
        :return: 含 removed 与 kept 的回收结果
        :raise LookupError: 插件不存在，或 ``plugin_id`` 实为某个分身自身的实例 ID
        :raise RuntimeError: 安装事务状态无从确认，本次回收拒绝删除任何目录
        """
        if not self._inventory.plugin_exists(plugin_id):
            raise LookupError(f"插件 {plugin_id} 不存在")
        if self._inventory.clone_instance(plugin_id) is not None:
            raise LookupError(f"{plugin_id} 是分身实例，请使用源插件 ID 回收版本")
        referenced = self._inventory.referenced_versions(plugin_id)
        try:
            pending = bool(self._pending_installation(plugin_id))
        except Exception as error:  # noqa: BLE001 - 判据未知时必须拒绝删除
            self._logger.error(f"检查插件 {plugin_id} 的安装事务失败，跳过版本回收：{error}")
            raise RuntimeError(f"无法确认插件 {plugin_id} 的安装状态，拒绝版本回收") from error
        return recycle_plugin_version_directories(
            self._inventory.plugin_root(plugin_id),
            referenced,
            retention,
            has_pending_installation=pending,
        )

    def set_instance_version(
        self,
        instance_id: str,
        *,
        pinned_version: Optional[str] = None,
    ) -> tuple[bool, str]:
        """设置实例的版本绑定，并立即完成一次停止再启动。

        不跟随当前版本时校验目标版本已安装；如本次切换会让该插件的多个实例分处不同
        版本，先跑一次多版本并存静态体检，命中阻断原因即拒绝切换、不做任何改动。

        切换走停止再启动的完整生命周期，不做热替换：热替换等于在运行期换掉一个已注册
        事件、已起定时任务、可能有在途请求的实例。目标版本启动失败时已生效版本保持
        不动，以该版本重新启动完成回退；回退同样失败才判定本次切换失败，全程留日志。

        本体与分身共用这一个入口：``instance_id`` 等于某个源插件 ID 且该插件确实存在
        时按本体的版本绑定解析（从未绑定过时给出默认视图），写回时据此路由到本体或
        分身各自的持久化端口。

        :param instance_id: 实例ID，可以是分身实例 ID，也可以是源插件本体自身 ID
        :param pinned_version: 锚定的目标版本号；为空表示改为跟随当前版本
        :return: `(是否成功, 成功时为实例ID／失败时为可读原因)`
        """
        instance = self._resolve_instance(instance_id)
        if instance is None:
            return False, f"插件实例 {instance_id} 不存在"
        rejected = self._reject_before_switch(instance, pinned_version)
        if rejected is not None:
            return False, rejected

        requested_version = (pinned_version or "").strip() or None
        target_version = self._inventory.resolve_target_version(
            instance.source_plugin_id, requested_version
        )
        previous_version = self._inventory.running_version(instance_id)
        previous_running = self._inventory.running_instance(instance_id)
        # 单列即绑定：为空即跟随当前版本，非空即锚定。本体加载走 loader.load，该路径
        # 不接收 start 的 version 形参、源码目录只由这条绑定记录解析，因此锚定值必须
        # 先落盘再启动，否则本体会照旧按当前版本加载
        updated_instance = instance.model_copy(update={"pinned_version": requested_version})
        try:
            self._persist_binding(updated_instance)
        except Exception as error:  # noqa: BLE001 - 持久化失败不得进入停启流程
            self._restore_binding(instance, instance_id)
            self._logger.error(f"插件实例 {instance_id} 保存版本绑定失败：{error}")
            return False, f"保存插件实例 {instance_id} 的版本绑定失败"

        if not self._stop_before_switch(instance, instance_id):
            return False, f"切换插件实例 {instance_id} 失败：停止旧实例失败"

        status, mismatch = self._start_target_version(
            instance_id, requested_version, target_version
        )
        if status == PluginRuntimeStatus.ACTIVE and mismatch is None:
            if not self._refresh_registrations_safely(instance_id):
                running_version = self._inventory.running_version(instance_id)
                return False, (
                    f"版本切换完成但插件实例 {instance_id} 注册刷新失败，"
                    f"当前实际版本为 {running_version or '未知'}"
                )
            return True, instance_id

        if mismatch is not None:
            # 加载器在绑定目录消失等情况下会回落到当前版本并仍返回 ACTIVE。先清掉这个
            # 并非用户所求的实例，再恢复绑定并尝试启动切换前实际运行的版本
            self._logger.error(
                f"插件实例 {instance_id} 请求切换到版本 {target_version}，"
                f"实际加载的是 {mismatch}"
            )
        if not self._stop_failed_runtime(instance_id, previous_running):
            self._restore_binding(instance, instance_id)
            self._refresh_registrations_safely(instance_id)
            return False, f"切换到版本 {target_version} 失败，清理错误运行实例失败"

        return self._recover_previous_version(
            instance, instance_id, target_version, previous_version
        )

    def _resolve_instance(self, instance_id: str) -> Optional[PluginInstance]:
        """把实例 ID 解析成一条绑定记录，分身优先、回落到同名源插件本体。"""
        instance = self._inventory.clone_instance(instance_id)
        if instance is not None:
            return instance
        if self._inventory.plugin_exists(instance_id):
            return self._inventory.host_instance(instance_id)
        return None

    def _reject_before_switch(
        self,
        instance: PluginInstance,
        pinned_version: Optional[str],
    ) -> Optional[str]:
        """在动任何持久化之前判定本次切换是否应当被直接拒绝。

        三条判据都必须排在写绑定之前：安装在途时磁盘上的版本目录正在变化，切过去可能
        落到一份写了一半的源码上；目标版本没装则连启动都无从谈起；写法不支持并存时
        真正切过去必然在运行期出怪事，把故障提前到这里比让它炸在加载时便宜得多。

        :param instance: 待切换的实例绑定
        :param pinned_version: 请求锚定的版本号，为空表示改为跟随当前版本
        :return: 拒绝说明；可以继续切换时为 None
        """
        try:
            if self._pending_installation(instance.source_plugin_id):
                return f"插件 {instance.source_plugin_id} 正在安装或写入，拒绝切换版本"
        except Exception as error:  # noqa: BLE001 - 安装状态未知时失败关闭
            self._logger.error(
                f"检查插件 {instance.source_plugin_id} 的安装事务失败：{error}"
            )
            return f"无法确认插件 {instance.source_plugin_id} 的安装状态"

        requested_version = (pinned_version or "").strip() or None
        target_version = self._inventory.resolve_target_version(
            instance.source_plugin_id, requested_version
        )
        if requested_version is not None and target_version is None:
            return f"插件 {instance.source_plugin_id} 未安装版本 {requested_version}"
        if not target_version:
            return None
        # 跟随当前版本同样可能把实例从旧版本切到当前版本，因此它也要过这道守卫
        if not self._inventory.creates_version_coexistence(instance, target_version):
            return None
        installed = self._inventory.installed_versions(instance.source_plugin_id)
        blockers = self._multi_version_blockers(
            instance.source_plugin_id.lower(), list(installed.values())
        )
        if not blockers:
            return None
        return (
            f"插件 {instance.source_plugin_id} 的写法不支持多版本并存，"
            "拒绝切换：" + "；".join(blockers)
        )

    def _stop_before_switch(self, instance: PluginInstance, instance_id: str) -> bool:
        """停止旧实例，未收敛即恢复绑定并中止本次切换。"""
        try:
            stop_result = self._stop(instance_id)
        except Exception as error:  # noqa: BLE001 - 停止失败时恢复旧绑定
            self._restore_binding(instance, instance_id)
            self._logger.error(f"插件实例 {instance_id} 停止失败：{error}")
            return False
        if stop_result is False:
            self._restore_binding(instance, instance_id)
            self._logger.error(f"插件实例 {instance_id} 停止未收敛")
            return False
        return True

    def _start_target_version(
        self,
        instance_id: str,
        requested_version: Optional[str],
        target_version: Optional[str],
    ) -> tuple[Optional[PluginRuntimeStatus], Optional[str]]:
        """启动目标版本，并核对实际生效版本是否就是请求的那一个。"""
        try:
            results = self._start(instance_id, requested_version)
        except Exception as error:  # noqa: BLE001 - 统一按加载失败执行补偿
            results = {}
            self._logger.error(f"插件实例 {instance_id} 启动目标版本失败：{error}")
        status = self._result_status(results, instance_id)
        mismatch = (
            self._effective_version_mismatch(instance_id, target_version)
            if status == PluginRuntimeStatus.ACTIVE
            else None
        )
        return status, mismatch

    @staticmethod
    def _result_status(
        results: dict[str, PluginRuntimeStatus], instance_id: str
    ) -> Optional[PluginRuntimeStatus]:
        """按大小写不敏感实例 ID 读取生命周期结果。"""
        if not isinstance(results, dict):
            return None
        target = instance_id.casefold()
        return next(
            (status for key, status in results.items() if key.casefold() == target),
            None,
        )

    def _restore_binding(self, instance: PluginInstance, instance_id: str) -> bool:
        """恢复切换前的绑定，并把补偿失败转成日志与布尔结果。"""
        try:
            self._persist_binding(instance)
            return True
        except Exception as error:  # noqa: BLE001 - 保留原始失败上下文
            self._logger.error(f"插件实例 {instance_id} 恢复原版本绑定失败：{error}")
            return False

    def _stop_failed_runtime(self, instance_id: str, previous_running: Any | None) -> bool:
        """清理目标启动留下的运行对象，避免错误版本继续占用路由与资源。"""
        current = self._inventory.running_instance(instance_id)
        if current is previous_running and current is not None:
            return True
        try:
            # 即使生命周期没有把失败实例放进运行表，stop 仍负责清掉失败导入留下的模块
            # 缓存、分类与宿主资源；否则本体回退时加载器会复用坏版本的缓存模块，一次
            # 失败会把原本可用的旧版本一起拖死
            result = self._stop(instance_id)
            return result is not False
        except Exception as error:  # noqa: BLE001 - 清理失败仍需返回主错误
            self._logger.error(f"插件实例 {instance_id} 清理错误版本失败：{error}")
            return False

    def _refresh_registrations_safely(self, instance_id: str) -> bool:
        """在版本切换完成后刷新该实例的宿主注册投影。"""
        try:
            self._refresh_registrations(instance_id)
            return True
        except Exception as error:  # noqa: BLE001 - 注册刷新不得改变已完成的切换
            self._logger.warning(f"插件实例 {instance_id} 注册刷新失败：{error}")
            return False

    def _recover_previous_version(
        self,
        instance: PluginInstance,
        instance_id: str,
        target_version: Optional[str],
        previous_version: Optional[str],
    ) -> tuple[bool, str]:
        """恢复切换前实际运行的版本，并在恢复失败时清理残留实例。"""
        if not previous_version or previous_version == target_version:
            self._restore_binding(instance, instance_id)
            self._logger.error(
                f"插件实例 {instance_id} 切换到版本 {target_version} 失败，"
                "没有可回退的已生效运行版本"
            )
            # 目标启动失败后通常没有运行对象；即便目标加载器已经写进了部分运行态，也
            # 必须让宿主重建注册投影，撤销仍指向旧实例的 API、任务与命令
            self._refresh_registrations_safely(instance_id)
            if target_version is None:
                return False, "切换为跟随当前版本失败，请查看插件日志"
            return False, f"切换到版本 {target_version} 失败，请查看插件日志"

        self._logger.error(
            f"插件实例 {instance_id} 切换到版本 {target_version} 失败，"
            f"已生效版本 {previous_version} 保持不变，正在以该版本重新启动"
        )
        # 本体的 loader.load 只按持久化绑定解析源码，够不到 start 的 version 形参。
        # 先临时钉住实际的旧版本，等回退实例真正启动后再恢复原来的绑定语义
        fallback_binding = instance.model_copy(update={"pinned_version": previous_version})
        if not self._restore_binding(fallback_binding, instance_id):
            self._restore_binding(instance, instance_id)
            self._refresh_registrations_safely(instance_id)
            return False, f"切换到版本 {target_version} 失败，恢复原版本绑定失败"
        try:
            fallback_results = self._start(instance_id, previous_version)
        except Exception as error:  # noqa: BLE001 - 回退失败必须可读返回
            fallback_results = {}
            self._logger.error(f"插件实例 {instance_id} 回退启动失败：{error}")
        fallback_status = self._result_status(fallback_results, instance_id)
        fallback_mismatch = self._effective_version_mismatch(instance_id, previous_version)
        if fallback_status == PluginRuntimeStatus.ACTIVE and fallback_mismatch is None:
            return self._settle_fallback_success(
                instance, instance_id, target_version, previous_version
            )

        self._stop_failed_runtime(instance_id, None)
        self._restore_binding(instance, instance_id)
        # 目标与回退都失败时旧版本已经被成功停掉，不能留下旧路由、调度与命令继续指向
        # 一个不存在的实例。按实际运行表刷新，空实例会撤销旧注册
        self._refresh_registrations_safely(instance_id)
        self._logger.error(
            f"插件实例 {instance_id} 以原版本 {previous_version} 回退启动同样失败"
        )
        detail = f"，实际加载的是 {fallback_mismatch}" if fallback_mismatch else ""
        return False, (
            f"切换到版本 {target_version} 失败，回退到原版本 {previous_version} 同样失败{detail}"
        )

    def _settle_fallback_success(
        self,
        instance: PluginInstance,
        instance_id: str,
        target_version: Optional[str],
        previous_version: str,
    ) -> tuple[bool, str]:
        """回退启动成功后刷新注册并恢复切换前的绑定语义。

        绑定恢复必须排在回退启动之后：提前恢复会让本体按新的当前版本解析源码，忽略
        回退时传入的旧版本。整条路径无论如何都返回失败——用户要的切换没有成功。
        """
        refresh_ok = self._refresh_registrations_safely(instance_id)
        if not self._restore_binding(instance, instance_id):
            self._refresh_registrations_safely(instance_id)
            return False, (
                f"切换到版本 {target_version} 失败，已回退到原版本 {previous_version}，"
                "但恢复原版本绑定失败"
            )
        if not refresh_ok:
            return False, (
                f"切换到版本 {target_version} 失败，已回退到原版本 {previous_version}，"
                "但注册刷新失败"
            )
        return False, f"切换到版本 {target_version} 失败，已回退到原版本 {previous_version}"

    def _effective_version_mismatch(
        self,
        instance_id: str,
        target_version: Optional[str],
    ) -> Optional[str]:
        """核对本次启动实际生效的版本，与目标版本不符时返回实际版本。

        实际生效版本直接从运行中的插件对象读取；运行对象缺少版本声明时无从核对，按
        相符处理，不因判据缺失把一次成功的切换报成失败。

        :param instance_id: 实例ID
        :param target_version: 本次请求切换到的版本，插件尚无任何已装版本时为空
        :return: 实际生效且与目标不符的版本号；相符或无从核对时为 None
        """
        if not target_version:
            return None
        effective = self._inventory.running_version(instance_id)
        if not effective or effective == target_version:
            return None
        return effective

    def _persist_binding(self, instance: PluginInstance) -> None:
        """按实例身份把版本绑定写回本体或分身各自的持久化端口。"""
        if instance.is_host:
            self._save_host_instance(instance)
        else:
            self._save_instance(instance)
