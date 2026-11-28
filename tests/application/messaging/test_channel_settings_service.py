"""
渠道配置服务的 revision、归属、凭据保护与并发写回归。
"""

import asyncio

import pytest
from pydantic import ValidationError

from app.application.messaging.channel.catalog import project_runtime_channels
from app.application.messaging.channel.settings import (
    ChannelSettingsConflict,
    ChannelSettingsService,
    CommittedChannelSettingsError,
)
from app.schemas.channel import (
    ChannelCardOrder,
    ChannelConnectionCreate,
    ChannelConnectionDelete,
    ChannelConnectionEdit,
    ChannelSettings,
    InteractionPolicy,
    InteractionPolicyEdit,
    NotificationRouteEdit,
)
from app.schemas.system import NotificationConf
from app.schemas.types import SystemConfigKey
from tests.support.messaging.channel_settings import _Configuration


@pytest.mark.asyncio
async def test_settings_write_uses_separate_revisions_and_legacy_only_imports_once():
    """
    通知和交互分别保存各自的版本，重读旧键不覆盖新设置或凭据。
    """
    config = _Configuration([
        {
            "id": "tg", "type": "telegram", "name": "Telegram", "enabled": True,
            "config": {"TELEGRAM_TOKEN": "fixture-token"}, "switchs": ["下载"],
        },
        {"id": "push", "type": "webpush", "name": "浏览器", "enabled": False},
    ])
    service = ChannelSettingsService(config)
    initial = service.read()
    assert [item.connection_id for item in initial.interactions] == ["tg"]
    assert initial.interactions[0].admission == "manual"
    assert initial.admission_modes["tg"] == ("manual", "manual_rules", "rules", "open")
    assert initial.rule_kinds["tg"] == ("user", "group", "private")
    assert "fixture-token" not in initial.model_dump_json()

    notify, interact = await asyncio.gather(
        service.edit_notification("tg", NotificationRouteEdit(enabled=False, message_types=(), expected_revision=1)),
        service.edit_interaction("tg", InteractionPolicyEdit(enabled=True, expected_revision=1)),
    )
    assert (notify.enabled, interact.enabled, notify.revision, interact.revision) == (False, True, 2, 2)
    assert config.events == [SystemConfigKey.ChannelSettings, SystemConfigKey.ChannelSettings]
    with pytest.raises(ChannelSettingsConflict):
        await service.edit_notification("tg", NotificationRouteEdit(enabled=True, message_types=(), expected_revision=1))

    changed = await service.edit_connection("tg", ChannelConnectionEdit(name="重命名", enabled=True, expected_revision=1))
    assert changed.identity_namespace == initial.connections[0].identity_namespace
    assert "fixture-token" not in str(service.read_legacy())
    config.state[SystemConfigKey.Notifications] = []
    assert service.read().notifications[0] == notify
    stored = config.get(SystemConfigKey.ChannelSettings)
    assert stored["connections"]["tg"]["provider_config"]["TELEGRAM_TOKEN"] == "fixture-token"

    with pytest.raises(ChannelSettingsConflict):
        await service.replace_legacy([NotificationConf(
            id="tg", name="重命名", type="telegram", enabled=True,
            config={"TELEGRAM_TOKEN": "another-account"},
        ), NotificationConf(id="push", name="浏览器", type="webpush")])
    assert config.get(SystemConfigKey.ChannelSettings) == stored



@pytest.mark.asyncio
async def test_remove_connection_preserves_history_and_rejects_stale_writes():
    """
    另一用途的保存使移除确认过期。成功移除后删除完整配置，新建同名连接分配新的身份。
    """
    legacy = [NotificationConf(id="tg", name="机器人", type="telegram", enabled=True,
                               config={"private": "fixture"}),
              NotificationConf(id="push", name="浏览器", type="webpush", enabled=True)]
    config = _Configuration([item.model_dump() for item in legacy])

    async def reconcile(previous, current):
        """
        删除后凭据清理只读取已经提交的当前配置。
        """
        assert "tg" not in config.get(SystemConfigKey.ChannelSettings)["connections"]
        if any(item.id == "tg" for item in previous):
            assert [item.id for item in current] == ["push"]

    service = ChannelSettingsService(config, reconcile=reconcile)
    request = ChannelConnectionDelete(expected_revision=1, notification_revision=1, interaction_revision=1)
    await service.edit_interaction("tg", InteractionPolicyEdit(enabled=False, expected_revision=1))
    with pytest.raises(ChannelSettingsConflict, match="配置已更新"):
        await service.delete_connection("tg", request)
    before = service.read()
    old = before.connections[0]
    removed = await service.delete_connection("tg", request.model_copy(update={"interaction_revision": 2}))
    assert not removed.enabled and removed.revision == 2
    stored = ChannelSettings.model_validate(config.get(SystemConfigKey.ChannelSettings))
    assert "tg" not in stored.connections and "tg" not in stored.notifications and "tg" not in stored.interactions
    assert all("tg" not in order for order in stored.orders.values())
    assert [record.id for record in service.read().connections] == ["push"]
    assert [record["id"] for record in service.read_legacy()] == ["push"]

    for update in (
        service.edit_connection("tg", ChannelConnectionEdit(name="旧机器人", enabled=True, expected_revision=2)),
        service.edit_notification("tg", NotificationRouteEdit(enabled=True, message_types=(), expected_revision=1)),
    ):
        with pytest.raises(KeyError):
            await update
    new = await service.create_connection(ChannelConnectionCreate(
        name="机器人", provider="telegram", provider_config={"private": "replacement"},
    ))
    assert new.id != old.id and new.identity_namespace != old.identity_namespace
    current = ChannelSettings.model_validate(config.get(SystemConfigKey.ChannelSettings))
    assert not current.notifications[new.id].enabled
    assert not current.interactions[new.id].enabled and current.interactions[new.id].admission == "manual"



@pytest.mark.asyncio
async def test_same_name_connection_writes_cannot_make_legacy_routing_ambiguous():
    """
    并发创建只能保存一个连接，重命名冲突及大小写变体不改变已有身份。
    """
    config = _Configuration([{"id": "tg", "type": "telegram", "name": "原连接", "enabled": True}])
    service = ChannelSettingsService(config)
    created = await asyncio.gather(
        service.create_connection(ChannelConnectionCreate(name="New Bot", provider="plugin-one", provider_config={})),
        service.create_connection(ChannelConnectionCreate(name=" new bot ", provider="plugin-two", provider_config={})),
        return_exceptions=True,
    )
    (conflict,) = (result for result in created if isinstance(result, ValidationError))
    assert conflict.errors()[0]["type"] == "channel_connection_name_conflict"
    current = service.read()
    assert len(current.connections) == len(current.notifications) == 2
    assert len(config.events) == 1

    with pytest.raises(ValidationError, match="连接名称已存在"):
        await service.edit_connection("tg", ChannelConnectionEdit(name="NEW BOT", enabled=False, expected_revision=1))
    assert service.read() == current
    assert len(config.events) == 1

    changed = await service.edit_connection("tg", ChannelConnectionEdit(name="新名称", enabled=True, expected_revision=1))
    assert changed.id == changed.identity_namespace == "tg"



@pytest.mark.asyncio
async def test_plugin_notification_type_is_preserved_without_interaction_capability():
    """
    混合配置中的插件类型随内置渠道导入，始终只生成通知资源。
    """
    config = _Configuration([
        {"id": "tg", "type": "telegram", "name": "Telegram", "enabled": True},
        {"id": "custom", "type": "plugin-notify", "name": "插件提醒", "enabled": True, "config": {"profile": "alpha"}},
    ])
    service = ChannelSettingsService(config)
    assert [item.provider for item in service.read().connections] == ["telegram", "plugin-notify"]

    await service.edit_notification("tg", NotificationRouteEdit(enabled=False, message_types=(), expected_revision=1))
    snapshot = ChannelSettings.model_validate(config.get(SystemConfigKey.ChannelSettings))
    projected = {row.id: row for row in project_runtime_channels(snapshot)}
    assert projected["custom"].type == "plugin-notify"
    assert projected["custom"].config == {"profile": "alpha"}
    assert projected["custom"].enabled and projected["custom"].notification_enabled
    assert projected["custom"].interaction_enabled is False
    assert "custom" not in service.read().admission_modes
    assert next(row for row in service.read_legacy() if row["id"] == "custom")["type"] == "plugin-notify"

    created = await service.create_connection(
        ChannelConnectionCreate(name="新插件提醒", provider="second-plugin", provider_config={}),
    )
    assert created.provider == "second-plugin" and not created.enabled
    assert created.id not in service.read().admission_modes



@pytest.mark.asyncio
async def test_stale_legacy_form_cannot_undo_shared_connection_edit():
    """
    旧版表单带着旧名称和启用状态提交时，保留新版最近保存的连接。
    """
    legacy = NotificationConf(id="tg", name="旧名称", type="telegram", enabled=True)
    config = _Configuration([legacy.model_dump()])
    service = ChannelSettingsService(config)
    await service.edit_connection("tg", ChannelConnectionEdit(name="新名称", enabled=False, expected_revision=1))
    with pytest.raises(ChannelSettingsConflict, match="连接配置已更新"):
        await service.replace_legacy([legacy])
    current = service.read().connections[0]
    assert (current.name, current.enabled, current.revision) == ("新名称", False, 2)



@pytest.mark.asyncio
async def test_channel_admission_capabilities_match_write_constraints():
    """
    验证企业微信两模式可选策略、自定义网关限制及配置保存后的行为隔离。
    """
    bot_config = {"WECHAT_MODE": "bot", "WECHAT_BOT_ID": "bot-id", "WECHAT_BOT_SECRET": "fixture-secret"}
    config = _Configuration([
        {"id": "official", "type": "wechat", "name": "官方机器人", "enabled": True, "config": bot_config},
        {"id": "proxy", "type": "wechat", "name": "自定义机器人", "enabled": True,
         "config": {**bot_config, "WECHAT_BOT_WS_URL": "wss://test.invalid"}},
        {"id": "app", "type": "wechat", "name": "企业应用", "enabled": True, "config": {
            "WECHAT_CORPID": "corp", "WECHAT_APP_ID": "app", "WECHAT_ENCODING_AESKEY": "key", "WECHAT_TOKEN": "token",
        }},
    ])
    service = ChannelSettingsService(config)
    view = service.read()
    assert view.admission_modes == {
        "official": ("manual", "manual_rules", "rules", "open"),
        "proxy": ("manual", "open"),
        "app": ("manual", "manual_rules", "rules", "open"),
    }
    edit = InteractionPolicyEdit(
        enabled=True, expected_revision=1, admission="manual_rules",
        admission_rules=[{"kind": "group", "target": "g1", "scopes": ["search", "download"]}],
        auto_download="specified", auto_download_rules=[{"kind": "user", "target": "alice"}],
    )
    for unsupported in ("proxy", "app"):
        with pytest.raises(ChannelSettingsConflict, match="无法验证"):
            await service.edit_interaction(unsupported, edit)
    saved = await service.edit_interaction("official", edit)
    assert saved.admission == "manual_rules" and saved.auto_download == "specified"
    assert saved.auto_download_rules[0].target == "alice"
    assert service.read().interactions[1:] == view.interactions[1:]
    assert service.read().notifications == view.notifications
    assert "fixture-secret" not in service.read().model_dump_json()
    cleared = await service.edit_interaction("official", InteractionPolicyEdit(
        enabled=True, expected_revision=saved.revision, admission_rules=(), auto_download_rules=(),
    ))
    assert cleared.admission == "manual_rules" and not cleared.admission_rules
    assert cleared.auto_download == "specified" and not cleared.auto_download_rules



@pytest.mark.asyncio
async def test_connection_reconciliation_runs_after_commit_and_before_refresh():
    """
    两种写入口共用生命周期边界，失败后仍发布已提交配置。
    """
    config = _Configuration([{
        "id": "claw", "type": "wechatclawbot", "name": "ClawBot", "enabled": True,
    }])
    calls = []

    async def reconcile(before, after):
        """
        核对已提交名称是否只由稳定连接传给运行态。
        """
        stored = config.get(SystemConfigKey.ChannelSettings)["connections"]["claw"]["name"]
        calls.append((before[0].name, after[0].name))
        assert stored == after[0].name
        if len(calls) == 2:
            raise ValueError("模拟缓存不可用")

    service = ChannelSettingsService(config, reconcile=reconcile)
    await service.edit_notification("claw", NotificationRouteEdit(enabled=False, message_types=(), expected_revision=1))
    assert not calls
    await service.replace_legacy([NotificationConf(id="claw", name="旧客户端改名", type="wechatclawbot", enabled=True)])
    assert calls == [("ClawBot", "旧客户端改名")]

    with pytest.raises(CommittedChannelSettingsError) as saved:
        await service.edit_connection("claw", ChannelConnectionEdit(name="新名称", enabled=True, expected_revision=2))
    assert saved.value.data.name == "新名称"
    assert calls[-1] == ("旧客户端改名", "新名称")
    assert service.read().connections[0].name == "新名称"
    assert config.events == [SystemConfigKey.ChannelSettings] * 3



@pytest.mark.asyncio
async def test_orders_are_independent_and_reject_stale_card_sets():
    """
    页面只保存自己的顺序，删除或新建后的旧页面不能覆盖新顺序。
    """
    config = _Configuration([
        {"id": "tg", "name": "Telegram", "type": "telegram", "enabled": False, "config": {}},
        {"id": "qq", "name": "QQ", "type": "qqbot", "enabled": False, "config": {}},
        {"id": "push", "name": "Web Push", "type": "webpush", "enabled": False, "config": {}},
    ])
    service = ChannelSettingsService(config)
    initial = service.read()
    assert initial.orders == {"notification": ("tg", "qq", "push"), "interaction": ("tg", "qq")}
    await service.reorder("notification", ChannelCardOrder(
        expected_order=initial.orders["notification"], order=("push", "tg", "qq"),
    ))
    await service.reorder("interaction", ChannelCardOrder(expected_order=("tg", "qq"), order=("qq", "tg")))
    assert service.read().orders == {"notification": ("push", "tg", "qq"), "interaction": ("qq", "tg")}
    assert not config.events
    with pytest.raises(ChannelSettingsConflict):
        await service.reorder("interaction", ChannelCardOrder(expected_order=("tg", "qq"), order=("qq", "tg")))
    with pytest.raises(ValueError):
        await service.reorder("interaction", ChannelCardOrder(expected_order=("qq", "tg"), order=("tg", "tg")))



@pytest.mark.asyncio
async def test_platform_form_updates_values_without_exposing_or_overwriting_credentials():
    """
    二次编辑通过版本约束只提交允许的字段，不更换已保存的平台身份。
    """
    config = _Configuration([{
        "id": "qq", "name": "QQ", "type": "qqbot", "enabled": True,
        "config": {"QQ_APP_ID": "app", "QQ_APP_SECRET": "existing-secret", "QQ_GROUP_OPENID": "old"},
        "switchs": ["订阅"],
    }])
    service = ChannelSettingsService(config)
    form = service.read_connection_form("qq")
    assert form.values == {"QQ_APP_ID": "app"}
    assert "QQ_GROUP_OPENID" not in form.editable_fields
    route = service.read().notifications[0]
    assert route.rules and route.rules[1].target == "old"
    await service.edit_notification("qq", NotificationRouteEdit(
        enabled=True, rules=(route.rules[1].model_copy(update={"target": "new"}),), expected_revision=route.revision,
    ))
    assert "QQ_APP_SECRET" in form.editable_fields
    saved = await service.edit_connection("qq", ChannelConnectionEdit(
        name="QQ", enabled=True, expected_revision=form.revision,
        provider_config={"QQ_APP_SECRET": ""},
    ))
    snapshot = config.get(SystemConfigKey.ChannelSettings)
    assert snapshot["connections"]["qq"]["provider_config"] == {
        "QQ_APP_ID": "app", "QQ_APP_SECRET": "existing-secret",
    }
    with pytest.raises(ValueError, match="平台身份"):
        await service.edit_connection("qq", ChannelConnectionEdit(
            name="QQ", enabled=True, expected_revision=saved.revision, provider_config={"QQ_APP_ID": "another"},
        ))
    assert service.read().notifications[0].rules[0].target == "new"
    assert service.read().rule_kinds["qq"] == ("group", "user")
    await service.edit_interaction("qq", InteractionPolicyEdit(
        enabled=True, expected_revision=1, admission="open",
    ))



@pytest.mark.parametrize("mode", ["manual_allowlist", "manual_exemption", "exemption"])
def test_intermediate_policy_modes_are_rejected(mode):
    """
    最终设置只接收人工审批、人工与规则、规则、无需审批四种模式。
    """
    with pytest.raises(ValueError):
        InteractionPolicy(connection_id="qq", identity_namespace="qq", enabled=True, revision=1, admission=mode)



@pytest.mark.asyncio
async def test_legacy_client_cannot_reuse_deleted_identity():
    """
    旧客户端重传已删除 ID 时仍分配新身份，避免恢复旧授权和在途任务。
    """
    config = _Configuration([{"id": "old", "name": "Same", "type": "telegram"}])
    service = ChannelSettingsService(config)
    await service.delete_connection("old", ChannelConnectionDelete(
        expected_revision=1, notification_revision=1, interaction_revision=1,
    ))
    await service.replace_legacy([NotificationConf(id="old", name="Same", type="telegram")])
    connection = service.read().connections[0]
    assert connection.id != "old" and connection.identity_namespace != "old"



@pytest.mark.asyncio
async def test_wechat_bot_protected_fields_and_unverified_gateway_remain_closed():
    """
    智能机器人只可修改当前身份的密钥；非官方网关不能原地编辑受保护的连接参数。
    """
    from app.modules.wechat.channel import WechatPlatform
    source = _Configuration([{
        "id": "bot", "name": "bot", "type": "wechat", "enabled": True,
        "config": {"WECHAT_MODE": "bot", "WECHAT_BOT_ID": "fixture-bot", "WECHAT_BOT_SECRET": "fixture-key"},
    }])
    service = ChannelSettingsService(source)
    form = service.read_connection_form("bot")
    assert form.editable_fields == ("WECHAT_BOT_SECRET",)
    assert "WECHAT_BOT_SECRET" not in form.values
    await service.edit_connection("bot", ChannelConnectionEdit(
        name="bot", enabled=True, expected_revision=1, provider_config={"WECHAT_BOT_SECRET": "replacement-key"},
    ))
    record = ChannelSettings.model_validate(source.state[SystemConfigKey.ChannelSettings]).connections["bot"]
    platform = WechatPlatform()
    assert platform.credential_key(record) is None
    assert platform.probe_identity(record) is None
    unknown = record.model_copy(update={"provider_config": record.provider_config | {"WECHAT_BOT_WS_URL": "wss://fixture.invalid"}})
    assert platform.editable_fields(unknown) == ()
    assert platform.capabilities(unknown).rule_kinds == ()
    with pytest.raises(ValueError):
        platform.patch_config(unknown, {"WECHAT_BOT_SECRET": "new-key"})



@pytest.mark.asyncio
async def test_resource_service_rotation_requires_same_verified_platform_identity():
    """
    配置服务比较平台诊断事实，跨账号轮换被拒绝，核验失败保留旧凭据并暂停收发。
    """
    from app.schemas.channel import ChannelCredentialRotation

    source = _Configuration([{
        "id": "first", "name": "first", "type": "telegram", "enabled": True,
        "config": {"TELEGRAM_TOKEN": "original"},
    }])
    observed = []

    async def probe(connection):
        """
        返回协议边界产生的已确认账号事实，不参与业务授权。
        """
        secret = connection.provider_config["TELEGRAM_TOKEN"]
        observed.append(secret)
        return {"original": "same", "replacement": "same", "foreign": "other"}.get(secret)

    service = ChannelSettingsService(source, probe=probe)
    initial, = service.read().connections
    changed = await service.rotate_credential("first", ChannelCredentialRotation(secret="replacement", expected_revision=1))
    assert changed.identity_namespace == initial.identity_namespace and changed.revision == 2
    assert observed == ["original", "replacement"]
    assert "replacement" not in service.read().model_dump_json()
    with pytest.raises(ChannelSettingsConflict, match="另一个平台账号"):
        await service.rotate_credential("first", ChannelCredentialRotation(secret="foreign", expected_revision=2))
    assert service.read().connections[0].revision == 2
    paused = await service.rotate_credential("first", ChannelCredentialRotation(secret="unverifiable", expected_revision=2))
    assert paused.credential_status == "verification_required"
    current = ChannelSettings.model_validate(source.state[SystemConfigKey.ChannelSettings])
    assert current.connections["first"].provider_config["TELEGRAM_TOKEN"] == "replacement"
    assert not project_runtime_channels(current)[0].enabled
