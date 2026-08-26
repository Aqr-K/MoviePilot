"""内建模块外挂为插件的可行性验证：分发顺序与渠道能力接管。

以 `app/modules/discord`（capability.toml 声明 priority=4、service_capability="notification"、
subtype="Discord"）为样本，验证把内建渠道模块改写成 `_PluginBase` 插件后：

- 分发顺序是否与它仍在内核时一致（``PluginProviderSource`` 硬编码排在
  ``HostModuleProviderSource`` 之前，而内建模块之间按 ``get_priority()`` 升序）；
- 渠道能力能否由 ``provides_channel_capabilities()`` 等价接管
  （``ChannelCapabilityManager`` 取用侧内建静态表优先）。

用例只读生产代码，不改动 `app/modules/discord`。
"""

from __future__ import annotations

import threading
from typing import Any, Iterator, Optional

import pytest

from app.runtime.extensions.contract.declaration import ModuleDeclaration
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.projection.dispatcher import ModuleInvocationDispatcher
from app.runtime.extensions.projection.plugin import PluginProjection
from app.schemas.notification import (
    ChannelCapabilities,
    ChannelCapabilityManager,
    channel_identity,
    resolve_channel,
)
from app.schemas.types import NotificationChannel


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _ChannelModule:
    """最小内建渠道模块替身：只带优先级、展示名与两个渠道方法。"""

    def __init__(self, name: str, priority: int) -> None:
        """记录模块展示名与仲裁优先级。

        :param name: 模块展示名
        :param priority: 同一方法名下的仲裁顺序，数值越小越先
        """
        self._name = name
        self._priority = priority

    def get_name(self) -> str:
        """返回模块展示名。"""
        return self._name

    def get_priority(self) -> int:
        """返回模块仲裁优先级。"""
        return self._priority

    def send_direct_message(self, **_kwargs: Any) -> str:
        """认领一次单播直发，返回本模块标识作为可辨认的应答。"""
        return self._name

    def post_message(self, **_kwargs: Any) -> str:
        """认领一次多播通知，返回本模块标识作为可辨认的应答。"""
        return self._name


class _HostModuleCatalog(ModuleManager):
    """复用 `ModuleManager` 真实索引与排序实现的宿主模块目录替身。

    只替换「哪些实例在运行」这一个事实，`providers_for` 与 `get_running_modules`
    仍走生产实现，因此本用例断言的排序就是宿主真实使用的那一份。
    """

    def __init__(self, modules: tuple[Any, ...]) -> None:  # noqa: D107 - 见类文档
        self._lock = threading.RLock()
        self._modules = {}
        self._running_modules = {module.get_name(): module for module in modules}
        self._running_generation = 0
        self._capability_index = None
        self._capability_index_generation = -1
        self._snapshot = modules

    def _running_snapshot(self) -> tuple[Any, ...]:
        """返回预置的运行实例快照。"""
        return self._snapshot


def _host_catalog(modules: tuple[Any, ...]) -> _HostModuleCatalog:
    """构造宿主模块目录替身，绕开 `ModuleManager` 的单例与清单发现。

    :param modules: 视为运行中的宿主模块实例
    :return: 目录替身
    """
    catalog = _HostModuleCatalog.__new__(_HostModuleCatalog)
    _HostModuleCatalog.__init__(catalog, modules)
    return catalog


class _EmptyHostCatalog:
    """不提供任何宿主模块的空目录。"""

    @staticmethod
    def get_running_modules(_method: str) -> tuple:
        """始终返回空序列。"""
        return ()

    @staticmethod
    def providers_for(_method: str) -> tuple:
        """始终返回空序列。"""
        return ()


class _OutsourcedChannelPlugin:
    """把渠道方法表声明式挂载出来的最小插件替身。"""

    def __init__(self, name: str, priority: int) -> None:
        """记录插件展示名与声明的方法表优先级。

        :param name: 插件展示名
        :param priority: `ModuleDeclaration.priority` 取值
        """
        self.plugin_name = name
        self._priority = priority

    def get_state(self) -> bool:
        """插件已启用。"""
        return True

    def get_name(self) -> str:
        """返回插件展示名。"""
        return self.plugin_name

    def provides_modules(self) -> list[ModuleDeclaration]:
        """声明与内建渠道模块同名的方法表。"""
        return [
            ModuleDeclaration(
                methods={
                    "send_direct_message": lambda **_kwargs: self.plugin_name,
                    "post_message": lambda **_kwargs: self.plugin_name,
                },
                priority=self._priority,
            )
        ]


class _PluginCatalog:
    """把 `PluginProjection.modules()` 适配为调度器消费的插件目录端口。"""

    def __init__(self, projection: Optional[PluginProjection]) -> None:
        """保存被适配的插件能力投影，为空时表示没有插件。"""
        self._projection = projection

    def get_plugin_modules(self) -> dict:
        """返回当前插件模块方法表快照。"""
        return self._projection.modules() if self._projection else {}


def _dispatcher(
    *,
    host_modules: tuple[Any, ...] = (),
    plugins: Optional[dict[str, Any]] = None,
) -> ModuleInvocationDispatcher:
    """构造同时接宿主模块目录与插件目录的调度器。

    :param host_modules: 视为运行中的宿主模块实例
    :param plugins: 实例键到运行态插件替身的映射
    :return: 调度器
    """
    return ModuleInvocationDispatcher(
        module_catalog=_host_catalog(host_modules) if host_modules else _EmptyHostCatalog(),
        plugin_catalog=_PluginCatalog(PluginProjection(plugins) if plugins else None),
        plugin_error_handler=lambda *a, **k: None,
        system_error_handler=lambda *a, **k: None,
        rate_limit_handler=lambda *a, **k: None,
    )


# 与 app/modules/*/capability.toml 里 metadata.priority 一致的真实取值
_TELEGRAM_PRIORITY = 0
_DISCORD_PRIORITY = 4


# ---------------------------------------------------------------------------
# Q2：外挂前后的分发顺序
# ---------------------------------------------------------------------------


def test_builtin_channel_unicast_follows_manifest_priority() -> None:
    """基线：两个内建渠道模块同时认领单播时，priority 更小的先应答。

    telegram（priority=0）与 discord（priority=4）都实现 ``send_direct_message``，
    该方法在 `app.application.orchestration._messaging` 里走 unicast，首个非空
    结果即最终答案，因此今天由 telegram 应答。
    """
    telegram = _ChannelModule("telegram", _TELEGRAM_PRIORITY)
    discord = _ChannelModule("discord", _DISCORD_PRIORITY)
    # 登记顺序刻意与优先级相反，确保断言的是排序而不是遍历先后
    dispatcher = _dispatcher(host_modules=(discord, telegram))

    assert dispatcher.unicast("send_direct_message") == "telegram"


def test_outsourced_channel_preempts_higher_priority_builtin_in_unicast() -> None:
    """外挂后 discord 抢在 telegram 之前应答单播，与外挂前结论相反。

    `ModuleInvocationDispatcher.__init__` 把 `PluginProviderSource` 硬编码排在
    `HostModuleProviderSource` 之前，插件目录里的方法表因此整体优先于任何内建
    模块，无论内建模块的 manifest priority 多小。
    """
    telegram = _ChannelModule("telegram", _TELEGRAM_PRIORITY)
    outsourced_discord = _OutsourcedChannelPlugin("discord", _DISCORD_PRIORITY)
    dispatcher = _dispatcher(
        host_modules=(telegram,),
        plugins={"DiscordPlugin": outsourced_discord},
    )

    assert dispatcher.unicast("send_direct_message") == "discord"


def test_declared_priority_cannot_restore_builtin_arbitration_order() -> None:
    """把声明优先级压到极低也换不回原顺序：跨源顺序不读 priority。

    外挂方案若指望用 `ModuleDeclaration.priority` 保住原有仲裁位次，这条用例说明
    该字段当前对跨源顺序完全不起作用。
    """
    telegram = _ChannelModule("telegram", _TELEGRAM_PRIORITY)
    outsourced_discord = _OutsourcedChannelPlugin("discord", priority=9999)
    dispatcher = _dispatcher(
        host_modules=(telegram,),
        plugins={"DiscordPlugin": outsourced_discord},
    )

    assert dispatcher.unicast("send_direct_message") == "discord"


def test_builtin_channel_multicast_order_follows_manifest_priority() -> None:
    """基线：多播按 manifest priority 升序收集内建渠道的应答。"""
    telegram = _ChannelModule("telegram", _TELEGRAM_PRIORITY)
    discord = _ChannelModule("discord", _DISCORD_PRIORITY)
    dispatcher = _dispatcher(host_modules=(discord, telegram))

    assert dispatcher.multicast("post_message") == ["telegram", "discord"]


def test_outsourced_channel_multicast_moves_to_front() -> None:
    """外挂后 discord 在多播里排到全部内建渠道之前，发送次序随之改变。

    ``post_message`` 走多播（`app/application/orchestration/__init__.py` 把
    `self.multicast` 交给消息队列），全部认领方都会被调用，因此外挂改变的是发送
    次序而不是发送与否。
    """
    telegram = _ChannelModule("telegram", _TELEGRAM_PRIORITY)
    outsourced_discord = _OutsourcedChannelPlugin("discord", _DISCORD_PRIORITY)
    dispatcher = _dispatcher(
        host_modules=(telegram,),
        plugins={"DiscordPlugin": outsourced_discord},
    )

    assert dispatcher.multicast("post_message") == ["discord", "telegram"]


# ---------------------------------------------------------------------------
# Q3：渠道能力的接管
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_channel_registrations() -> Iterator[None]:
    """用例前后都清空扩展渠道能力登记，避免污染全局管理器。"""
    ChannelCapabilityManager.register_extension_capabilities("v3lite-probe", [])
    yield
    ChannelCapabilityManager.register_extension_capabilities("v3lite-probe", [])


def _probe_capabilities(channel: Any) -> ChannelCapabilities:
    """构造一份与内建静态表明显不同的渠道能力声明。

    :param channel: 渠道取值
    :return: 渠道能力声明
    """
    return ChannelCapabilities(
        channel=channel,
        capabilities=set(),
        max_message_length=4321,
    )


def test_extension_path_serves_non_builtin_channel_identity(
    _clean_channel_registrations: None,
) -> None:
    """扩展登记路径能为非内建标识提供完整的渠道能力查表。

    枚举里没有的标识按标识字符串登记与取用，`get_capabilities` 与
    `get_max_message_length` 都走同一条路，说明外挂后的渠道不依赖枚举成员。
    """
    identity = "v3lite-discord"
    ChannelCapabilityManager.register_extension_capabilities(
        "v3lite-probe", [_probe_capabilities(identity)]
    )

    resolved = ChannelCapabilityManager.get_capabilities(identity)

    assert resolved is not None
    assert ChannelCapabilityManager.get_max_message_length(identity) == 4321


def test_builtin_static_table_shadows_extension_registration(
    _clean_channel_registrations: None,
) -> None:
    """枚举成员与静态表还在时，插件登记的同一渠道被内建表整个压住。

    `ChannelCapabilityManager.get_capabilities` 先查内建静态表，命中即返回，
    扩展登记只在未命中时才被查到。因此「静态表让出该项」不是可选步骤：静态表
    不删，外挂插件的声明永远不生效，两者无法并存过渡。
    """
    ChannelCapabilityManager.register_extension_capabilities(
        "v3lite-probe", [_probe_capabilities(NotificationChannel.Discord)]
    )

    resolved = ChannelCapabilityManager.get_capabilities(NotificationChannel.Discord)

    assert resolved is not None
    # 取到的仍是内建静态表那一份（1800），而不是插件登记的 4321
    assert resolved.max_message_length == 1800
    assert ChannelCapabilityManager.get_max_message_length("Discord") == 1800


def test_unknown_channel_value_degrades_to_identity_string() -> None:
    """枚举成员被移除后，存量配置里的渠道取值退化为标识字符串而不是抛错。

    `resolve_channel` 命中不了内建索引就原样交出字符串，`channel_identity` 据此
    给出稳定标识，因此归一层本身不会因枚举成员消失而 `AttributeError`。
    """
    # 模拟枚举已移除 Discord 之后，存量取值走到的那条分支
    assert resolve_channel("v3lite-removed-member") == "v3lite-removed-member"
    assert channel_identity("v3lite-removed-member") == "v3lite-removed-member"
    # 无人登记该标识时交出 None，是可诊断的空结果
    assert ChannelCapabilityManager.get_capabilities("v3lite-removed-member") is None


def test_channel_name_attribute_access_breaks_for_extension_channel() -> None:
    """固定风险点：以 `channel.name` 取渠道名的调用方对字符串渠道会抛 AttributeError。

    `app/application/orchestration/interaction.py` 的两处 ``channel.name.lower()``
    只用 ``if channel`` 做真值守卫，非空字符串渠道同样为真，因此枚举成员被移除后
    这两处会抛 `AttributeError` 而不是降级。
    """
    channel = resolve_channel("v3lite-removed-member")

    with pytest.raises(AttributeError):
        _ = channel.name.lower()  # type: ignore[union-attr]
