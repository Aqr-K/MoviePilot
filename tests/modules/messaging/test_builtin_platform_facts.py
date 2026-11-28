"""
内置平台注册共存、规范主体事实与个人地址限制。
"""

import pytest

from app.application.messaging.channel import platform_catalog
from app.domain.authorization import channel_actor_ids


def test_all_builtin_protocol_owners_coexist_without_starting_clients():
    """
    同一清单目录保留全部内置平台，各 provider 有唯一宿主解析 owner。
    """
    providers = platform_catalog().providers()
    assert {entry.provider for entry in providers} == {
        "apppush", "dingtalk", "discord", "feishu", "qqbot", "slack",
        "synologychat", "telegram", "vocechat", "webpush", "wechat", "wechatclawbot",
    }
    assert len({entry.module_id for entry in providers}) == len(providers) == 12


@pytest.mark.parametrize("provider,raw,expected", [
    ("qqbot", "alice", ("alice",)),
    ("vocechat", "12", ("UID#12", "12")),
    ("vocechat", "UID#12", ("UID#12", "12")),
    ("telegram", "123", ("123",)),
])
def test_platform_emits_deterministic_person_identity_and_proven_aliases(provider, raw, expected):
    """
    平台拥有协议解析，通用领域只接收个人事实与确定性别名。
    """
    entry = platform_catalog().get(provider)
    assert entry is not None
    assert channel_actor_ids(entry.actor(raw)) == expected


@pytest.mark.parametrize("provider,raw", [("qqbot", "group:room"), ("qqbot", "GROUP:room"), ("vocechat", "GID#12")])
def test_group_fact_cannot_become_authorized_person(provider, raw):
    """
    平台声明的群组不能通过规范个人主体校验。
    """
    entry = platform_catalog().get(provider)
    assert entry is not None
    with pytest.raises(ValueError, match="个人"):
        channel_actor_ids(entry.actor(raw))


@pytest.mark.parametrize("provider,address", [("qqbot", "group:room"), ("vocechat", "GID#12"), ("wechat", "@all")])
def test_explicit_group_or_broadcast_is_not_private_delivery(provider, address):
    """
    单个个人目标校验拒绝群组与全体广播，不能冒充私聊地址。
    """
    entry = platform_catalog().get(provider)
    assert entry is not None
    with pytest.raises(PermissionError):
        entry.private_target(address)


@pytest.mark.parametrize("provider", ["apppush", "dingtalk", "discord", "feishu", "qqbot", "slack", "synologychat", "telegram", "vocechat", "webpush", "wechat", "wechatclawbot"])
def test_builtin_capability_projection_never_changes_admission_or_scopes(provider):
    """
    每个真实内置扩展都可惰性加载，能力和选项投影不能自行批准成员。
    """
    from app.schemas.channel import ChannelConnection, InteractionPolicy, NotificationRoute
    from app.schemas.message import Message

    entry = platform_catalog().get(provider)
    connection = ChannelConnection(id="fixture", name="Fixture", provider=provider, mode=entry.mode({}), identity_namespace="space", enabled=True, revision=1, provider_config={})
    policy = InteractionPolicy(connection_id=connection.id, identity_namespace="space", enabled=True, revision=1)
    projected = entry.import_options(connection, policy)
    assert projected.admission == "manual" and projected.admission_rules == ()
    assert entry.normalize_interaction(projected.model_dump())["admission"] == "manual"
    assert entry.export_interaction(projected)["admission"] == "manual"
    assert entry.form_values(connection).get("secret") is None
    assert isinstance(entry.editable_fields(connection), tuple)
    assert entry.runtime_config(connection, projected) is not connection.provider_config
    assert entry.legacy_rules(connection, NotificationRoute(connection_id="fixture", identity_namespace="space", enabled=False, revision=1)) in (None, ())
    assert entry.actor("123").kind == "person"
    assert entry.bound_address(Message()) is None
    parts = [Message(text="first")]
    assert entry.split_notification(parts) == parts
    assert entry.attachment_reference("file", "unknown://file") is None


@pytest.mark.parametrize("provider,kind,reference,method", [
    ("telegram", "image", "tg://file_id/image", "download_telegram_file_to_base64"),
    ("telegram", "audio", "tg://audio_file_id/audio", "download_telegram_file_bytes"),
    ("slack", "file", "https://files.invalid/file", "download_slack_file_to_data_url"),
    ("slack", "audio", "slack://file/file", "download_slack_file_bytes"),
    ("discord", "file", "discord://file/file", "download_discord_file_bytes"),
    ("qqbot", "audio", "qq://file/file", "download_qq_file_bytes"),
    ("vocechat", "image", "vocechat://file/file", "download_vocechat_image_to_data_url"),
    ("vocechat", "file", "vocechat://file/file", "download_vocechat_file_bytes"),
    ("synologychat", "file", "synology://file/file", "download_synologychat_file_bytes"),
    ("feishu", "image", "feishu://image/image", "download_feishu_image_to_data_url"),
    ("feishu", "audio", "feishu://file/file", "download_feishu_file_bytes"),
    ("wechat", "image", "wxwork://media_id/image", "download_wechat_image_to_data_url"),
    ("wechat", "audio", "wxwork://voice_media_id/audio", "download_wechat_media_bytes"),
    ("wechat", "file", "wxwork://file_media_id/file", "download_wechat_media_bytes"),
    ("wechatclawbot", "image", "wxclaw://image/image", "download_wechat_image_to_data_url"),
    ("wechatclawbot", "audio", "wxclaw://voice/audio", "download_wechat_media_bytes"),
])
def test_builtin_attachment_references_produce_existing_abi(provider, kind, reference, method):
    """
    平台只产生已有下载能力的计划，公共调用方无需理解协议引用。
    """
    plan = platform_catalog().get(provider).attachment_reference(kind, reference)
    assert plan.method == method
    assert plan.parameters


def test_discord_owns_command_registration_scope_and_validates_legacy_options():
    """
    Discord 专属命令作用域只在所属扩展解释并投影，不进入通用交互 DTO。
    """
    from app.schemas.channel import ChannelConnection, InteractionPolicy

    entry = platform_catalog().get("discord")
    connection = ChannelConnection(id="fixture", name="Fixture", provider="discord", mode="standard", identity_namespace="space", enabled=True, revision=1, provider_config={"DISCORD_GUILD_ID": "123"})
    policy = InteractionPolicy(connection_id="fixture", identity_namespace="space", enabled=True, revision=1)
    imported = entry.import_options(connection, policy)
    assert imported.platform_options == {"command_guild_id": "123"}
    assert entry.runtime_config(connection, imported)["DISCORD_COMMAND_GUILD_ID"] == "123"
    assert entry.export_interaction(imported)["command_guild_id"] == "123"
    assert entry.normalize_interaction({"command_guild_id": "123"}) == {"platform_options": {"command_guild_id": "123"}}
    assert entry.validate_interaction({"command_guild_id": " 123 "}) == {"command_guild_id": "123"}
    for options in ({"command_guild_id": "@all"}, {"command_guild_id": 123}, {"unknown": "123"}):
        with pytest.raises(ValueError):
            entry.validate_interaction(options)


@pytest.mark.parametrize("config,mode,expected", [
    ({"WECHAT_MODE": "bot", "WECHAT_BOT_ID": "fixture", "WECHAT_BOT_SECRET": "fixture-secret"}, "bot", ("user", "group", "private")),
    ({"WECHAT_MODE": "bot", "WECHAT_BOT_ID": "fixture", "WECHAT_BOT_SECRET": "fixture-secret", "WECHAT_BOT_WS_URL": "wss://custom.invalid"}, "bot", ()),
    ({"WECHAT_CORPID": "fixture", "WECHAT_APP_ID": "3", "WECHAT_ENCODING_AESKEY": "fixture-key", "WECHAT_TOKEN": "fixture-token"}, "app", ("user", "private")),
])
def test_wechat_capabilities_require_mode_specific_authenticated_facts(config, mode, expected):
    """
    自建应用、官方机器人和第三方网关的能力限制分别由企业微信扩展产生。
    """
    from app.schemas.channel import ChannelConnection

    entry = platform_catalog().get("wechat")
    connection = ChannelConnection(id="fixture", name="Fixture", provider="wechat", mode=entry.mode(config), identity_namespace="space", enabled=True, revision=1, provider_config=config)
    assert connection.mode == mode and entry.capabilities(connection).rule_kinds == expected
    assert "WECHAT_BOT_SECRET" not in entry.form_values(connection)
    assert "WECHAT_TOKEN" not in entry.form_values(connection)
    if config.get("WECHAT_BOT_WS_URL"):
        with pytest.raises(ValueError):
            entry.patch_config(connection, {"WECHAT_BOT_SECRET": "replacement"})
    else:
        editable = entry.editable_fields(connection)
        if editable:
            assert entry.patch_config(connection, {editable[0]: ""}) == config
    assert entry.credential_key(connection) == ("WECHAT_APP_SECRET" if mode == "app" else None)


@pytest.mark.parametrize("result", [{"is_bot": True, "id": 123}, {"is_bot": False, "id": 123}, {"is_bot": True, "id": True}, ValueError("invalid result")])
def test_telegram_identity_probe_confirms_bot_and_closes_client(monkeypatch, result):
    """
    官方诊断必须确认机器人，异常和非机器人结果均关闭客户端且不产生身份。
    """
    from unittest.mock import Mock

    from app.schemas.channel import ChannelConnection

    entry = platform_catalog().get("telegram")
    client = Mock()
    if isinstance(result, Exception):
        client.get_me.side_effect = result
    else:
        client.get_me.return_value = result
    monkeypatch.setattr("app.modules.telegram.botapi.TelegramBotApi", Mock(return_value=client))
    connection = ChannelConnection(id="fixture", name="Fixture", provider="telegram", mode="standard", identity_namespace="space", enabled=True, revision=1, provider_config={"TELEGRAM_TOKEN": "123:fixture"})
    assert entry.probe_identity(connection) == ("123" if result == {"is_bot": True, "id": 123} else None)
    client.close.assert_called_once()


def test_wechat_identity_diagnostic_and_explicit_targets_stay_platform_owned(monkeypatch):
    """
    应用诊断使用固定企业和应用身份；机器人旧群目标只生成会话地址，全体不能伪装个人。
    """
    from unittest.mock import Mock

    from app.schemas.channel import ChannelConnection, NotificationRule

    entry = platform_catalog().get("wechat")
    connection = ChannelConnection(id="fixture", name="Fixture", provider="wechat", mode="app", identity_namespace="space", enabled=True, revision=1, provider_config={"WECHAT_CORPID": "corp", "WECHAT_APP_ID": 3, "WECHAT_APP_SECRET": "fixture"})
    probe = Mock(return_value="corp:3")
    monkeypatch.setattr("app.modules.wechat.wechat.WeChat.probe_app_identity", probe)
    assert entry.probe_identity(connection) == "corp:3"
    probe.assert_called_once_with("corp", "3", "fixture")
    assert entry.probe_identity(connection.model_copy(update={"mode": "bot"})) is None
    for original, expected in [("group:room", ("conversation", "room", None)), ("user:alice", ("user", "alice", None)), ("alice", ("user", "alice", None))]:
        bot = connection.model_copy(update={"mode": "bot", "provider_config": {"WECHAT_BOT_CHAT_ID": original}})
        assert entry.legacy_addresses(bot) == (expected,)
        assert entry.conversation("group:room") == "room"
    for target in ("@all", "alice|bob"):
        with pytest.raises(ValueError):
            entry.validate_target(connection, NotificationRule(kind="user", target=target, message_types=("订阅",)))


@pytest.mark.parametrize("success", [True, False])
def test_clawbot_cache_reconciliation_uses_connection_identity_and_reports_failure(monkeypatch, success):
    """
    缓存对账归平台所有，连接改名沿用稳定 ID，失败可诊断而不改写已提交配置。
    """
    from unittest.mock import Mock

    from app.schemas.channel import ChannelConnectionInfo

    entry = platform_catalog().get("wechatclawbot")
    before = ChannelConnectionInfo(id="fixture", name="Old", provider="wechatclawbot", mode="standard", identity_namespace="space", enabled=True, revision=1)
    after = before.model_copy(update={"name": "New", "revision": 2})
    reconcile = Mock(return_value={"success": success})
    monkeypatch.setattr("app.modules.wechatclawbot.wechatclawbot.WechatClawBot.reconcile_cached_states", reconcile)
    entry.reconcile((before,), (before,))
    reconcile.assert_not_called()
    if success:
        entry.reconcile((before,), (after,))
    else:
        with pytest.raises(RuntimeError, match="缓存"):
            entry.reconcile((before,), (after,))
    assert reconcile.call_args.args[0][0]["id"] == reconcile.call_args.args[1][0]["id"] == "fixture"
    assert entry.manage("unsupported", {"saved_connection": True}) is None
    assert entry.manage("status", {}) is None
