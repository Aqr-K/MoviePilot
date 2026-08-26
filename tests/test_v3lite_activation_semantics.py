"""内建模块外挂为插件的可行性验证：``activation`` 语义能否由插件声明族承载。

`app/modules/discord/capability.toml` 声明 ``activation.policy = "when_configured"``
并给出 ``system_config_item`` selector（Notifications 里 ``type == "discord"`` 且
``enabled`` 为真的那条记录）。本文件核对宿主侧真正读取该声明的代码
（`app.runtime.extensions.lifecycle.host_module_adapter.should_run_host_module`），
再对照插件侧「方法表何时出现在分发目录里」的判据，判断两者是否等价。

用例只读生产代码，不改动 `app/modules/discord`。
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from app.runtime.capabilities.model import ActivationPolicy
from app.runtime.extensions.contract.declaration import (
    ModuleDeclaration,
    ServiceInstanceDeclaration,
)
from app.runtime.extensions.lifecycle.host_module_adapter import (
    HostModuleConfigSnapshot,
    build_host_module_registry,
    service_instance_declaration,
    should_run_host_module,
)
from app.runtime.extensions.projection.plugin import PluginProjection
from app.schemas.types import SystemConfigKey


_NOTIFICATIONS_KEY = SystemConfigKey.Notifications.value


@pytest.fixture(scope="module")
def discord_spec():
    """取出 discord 模块的真实 manifest 声明。"""
    registry = build_host_module_registry()
    spec = next(
        item for item in registry.list_specs() if item.id == "DiscordModule"
    )
    return spec


def _notifications_snapshot(*items: Any) -> HostModuleConfigSnapshot:
    """构造只含 Notifications 一族配置的宿主配置快照。

    :param items: Notifications 配置记录
    :return: 配置快照
    """
    return HostModuleConfigSnapshot(
        settings={},
        services={_NOTIFICATIONS_KEY: tuple(items)},
    )


def _notification_conf(service_type: str, enabled: bool) -> SimpleNamespace:
    """构造一条最小 Notifications 配置记录。

    :param service_type: 配置的类型标识
    :param enabled: 该条配置是否启用
    :return: 配置记录
    """
    return SimpleNamespace(type=service_type, enabled=enabled, name=service_type)


# ---------------------------------------------------------------------------
# 宿主侧：activation 的真实判据
# ---------------------------------------------------------------------------


def test_discord_manifest_declares_when_configured(discord_spec) -> None:
    """固定 discord 清单的 activation 形状，作为后续对照的基准。"""
    assert discord_spec.activation is ActivationPolicy.WHEN_CONFIGURED
    assert discord_spec.selector is not None
    assert discord_spec.selector.kind == "system_config_item"
    assert discord_spec.selector.config["key"] == _NOTIFICATIONS_KEY
    assert discord_spec.selector.config["match_value"] == "discord"
    assert _NOTIFICATIONS_KEY in discord_spec.watch


def test_host_module_not_run_without_matching_config(discord_spec) -> None:
    """没有 discord 配置时该模块不获得运行资源，分发目录里也就没有它。"""
    snapshot = _notifications_snapshot(_notification_conf("telegram", True))

    assert should_run_host_module(discord_spec, snapshot) is False


def test_host_module_not_run_when_matching_config_disabled(discord_spec) -> None:
    """配了 discord 但停用时同样不运行：selector 同时判定类型与启用位。"""
    snapshot = _notifications_snapshot(_notification_conf("discord", False))

    assert should_run_host_module(discord_spec, snapshot) is False


def test_host_module_runs_with_enabled_matching_config(discord_spec) -> None:
    """存在已启用的 discord 配置时该模块才运行。"""
    snapshot = _notifications_snapshot(_notification_conf("discord", True))

    assert should_run_host_module(discord_spec, snapshot) is True


def test_service_instance_declaration_reads_multi_instance(discord_spec) -> None:
    """``metadata.service_instance`` 的三项事实可被完整读出，可平移到插件声明。"""
    assert service_instance_declaration(discord_spec) == ("notification", "discord", True)


# ---------------------------------------------------------------------------
# 插件侧：方法表出现在分发目录里的判据
# ---------------------------------------------------------------------------


class _ConfigAgnosticPlugin:
    """方法表不随服务配置存在与否变化的插件替身。"""

    plugin_name = "外挂 discord"

    def __init__(self, enabled: bool = True) -> None:
        """记录插件自身的启用状态。"""
        self._enabled = enabled

    def get_state(self) -> bool:
        """返回插件自身的启用状态。"""
        return self._enabled

    def get_name(self) -> str:
        """返回插件展示名。"""
        return self.plugin_name

    def provides_modules(self) -> list[ModuleDeclaration]:
        """声明渠道方法表。"""
        return [ModuleDeclaration(methods={"post_message": lambda **_kw: None})]

    def provides_service_instances(self) -> list[Any]:
        """本用例只关心方法表，不声明服务实例类型。"""
        return []


def test_plugin_method_table_ignores_service_configuration() -> None:
    """插件方法表只看插件自身启用位，与 Notifications 里有没有 discord 配置无关。

    这与宿主 `when_configured` 的判据不是同一件事：一份 discord 配置都没有时，
    外挂插件仍然会作为 ``post_message`` 的提供者出现在分发目录里。
    """
    projection = PluginProjection({"DiscordPlugin": _ConfigAgnosticPlugin()})

    modules = projection.modules()

    assert [table for table in modules.values() if "post_message" in table]


def test_plugin_method_table_disappears_when_plugin_disabled() -> None:
    """插件停用即整张方法表消失，说明这条开关落在插件而不落在服务配置上。"""
    projection = PluginProjection(
        {"DiscordPlugin": _ConfigAgnosticPlugin(enabled=False)}
    )

    assert projection.modules() == {}


class _DiscordClientStub:
    """服务实例声明里的最小实现类，按 ``impl(name=..., **config)`` 构造。

    notification 族的取用链要求实现类在场 ``get_state()``，与真实 `Discord`
    客户端一致。
    """

    def __init__(self, name: Optional[str] = None, **_config: Any) -> None:
        """记录实例名。"""
        self.name = name

    def get_state(self) -> bool:
        """返回连通状态。"""
        return True


class _ConfigGatedPlugin(_ConfigAgnosticPlugin):
    """把 ``get_state()`` 自绑到服务配置存在性上的插件替身。"""

    def __init__(self, has_config: bool) -> None:
        """记录当前是否存在已启用的本渠道配置。"""
        super().__init__(enabled=has_config)
        self._service_declaration = ServiceInstanceDeclaration(
            capability="notification",
            type="discord",
            name="Discord",
            impl=_DiscordClientStub,
            multi_instance=True,
        )

    def provides_service_instances(self) -> list[Any]:
        """声明本插件提供的服务实例类型。"""
        return [self._service_declaration]


def test_config_gated_state_also_hides_the_service_type() -> None:
    """自绑 ``get_state()`` 复刻 `when_configured` 会连服务类型一起藏起来。

    `PluginProjection.provided_service_instances` 在 ``is_enabled()`` 为假时整体
    跳过该实例，因此「没有配置就不启用」的插件同时也不登记「可以配这个类型」——
    用户无从新建第一条 discord 配置，形成先有配置还是先有类型的死锁。
    """
    without_config = PluginProjection({"DiscordPlugin": _ConfigGatedPlugin(False)})
    with_config = PluginProjection({"DiscordPlugin": _ConfigGatedPlugin(True)})

    assert without_config.provided_service_instances() == {}
    assert with_config.provided_service_instances().get("DiscordPlugin")


def _module_tables(projection: PluginProjection) -> list[dict]:
    """列出投影里全部插件的方法表。

    :param projection: 插件能力投影
    :return: 方法表列表
    """
    return list(projection.modules().values())


def test_config_gated_state_hides_method_table_too() -> None:
    """同一条自绑还会让方法表在没有配置时一并消失，代价与收益都记在这里。"""
    without_config: Optional[PluginProjection] = PluginProjection(
        {"DiscordPlugin": _ConfigGatedPlugin(False)}
    )

    assert _module_tables(without_config) == []
