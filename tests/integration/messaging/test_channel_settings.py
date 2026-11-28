"""
验证共享渠道配置的事务、兼容投影、隐私和两项开关。
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.endpoints import notification
from app.api.endpoints import settings as settings_endpoint
from app.application.messaging.channel.catalog import project_runtime_channels
from app.application.messaging.channel.settings import (
    ChannelSettingsConflict,
    ChannelSettingsService,
)
from app.modules.telegram.module import TelegramModule
from app.schemas.channel import (
    ChannelConnectionCreate,
    ChannelConnectionEdit,
    ChannelCredentialRotation,
    ChannelSettings,
    InteractionPolicyEdit,
    NotificationRouteEdit,
)
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType, NotificationChannel, SystemConfigKey
from tests.support.messaging.channel_settings import _Configuration


def test_channel_settings_http_contract(monkeypatch):
    """
    管理员接口从同一配置事务读取连接并在冲突时保留其他资源。
    """
    source = _Configuration([{
        "id": "fixture", "name": "机器人", "type": "telegram", "enabled": True,
        "switchs": ["下载"], "config": {},
    }])
    monkeypatch.setattr(notification, "get_configured_system_config", lambda: source)
    monkeypatch.setattr(settings_endpoint, "get_configured_system_config", lambda: source)
    monkeypatch.setattr(notification, "get_channel_authorization",
                        lambda: SimpleNamespace(connection_reference_counts=lambda _: (2, 3)))
    app = FastAPI()
    app.include_router(notification.router)
    app.include_router(settings_endpoint.router)
    app.dependency_overrides[notification.get_current_active_superuser] = lambda: None
    app.dependency_overrides[settings_endpoint.get_current_active_superuser_async] = lambda: None
    with TestClient(app) as client:
        before = client.get("/channels")
        assert before.status_code == 200
        data = before.json()["data"]
        route, = data["notifications"]
        reference = client.get("/channels/fixture/references")
        assert reference.status_code == 200
        assert reference.json()["data"] == {"member_count": 2, "task_count": 3}
        assert client.get("/channels/missing/references").status_code == 404
        assert client.get("/setting/ChannelSettings").status_code == 404
        legacy = client.get("/setting/Notifications")
        assert legacy.status_code == 200 and legacy.json()["data"]["value"][0]["id"] == "fixture"
        payload = {"enabled": False, "expected_revision": route["revision"], "message_types": route["message_types"]}
        assert client.put("/channels/missing/notification", json=payload).status_code == 404
        edited = client.put("/channels/fixture/notification", json=payload)
        assert edited.status_code == 200
        assert edited.json()["data"]["enabled"] is False
        assert client.put("/channels/fixture/notification", json={**payload, "enabled": True}).status_code == 409
        assert client.get("/channels").json()["data"]["interactions"] == data["interactions"]
        removed = client.request("DELETE", "/channels/fixture/connection", json={
            "expected_revision": 1, "notification_revision": 2, "interaction_revision": 1,
        })
        assert removed.status_code == 200
        snapshot = client.get("/channels").json()["data"]
        assert snapshot["connections"] == [] and "reserved_names" not in snapshot
        collision = client.post("/channels/connections", json={
            "name": "机器人", "provider": "synologychat", "provider_config": {},
        })
        assert collision.status_code == 200
        assert collision.json()["data"]["name"] == "机器人"
        assert collision.json()["data"]["id"] != "fixture"


@pytest.mark.asyncio
async def test_slack_rotation_uses_confirmed_workspace_and_bot_after_old_token_expires(monkeypatch):
    """
    新建时保存平台身份，轮换拒绝不同工作区或机器人并保留原有设置。
    """
    from app.startup.initializers.modules import _probe_channel_identity

    config = _Configuration([])
    service = ChannelSettingsService(config, probe=_probe_channel_identity)
    accounts = {
        "xoxb-original": ("T1", "B1"),
        "xoxb-replacement": ("T1", "B1"),
        "xoxb-other-team": ("T2", "B1"),
        "xoxb-other-bot": ("T1", "B2"),
    }
    responses = []

    def transport(*, verify, timeout, headers):
        """
        模拟固定官方接口及令牌过期，不启动 Socket Mode。
        """
        assert verify is True and timeout == 8
        token = headers["Authorization"].removeprefix("Bearer ")
        team, bot = accounts[token]
        response = Mock(status_code=200)
        response.json.return_value = {"ok": True, "team_id": team, "bot_id": bot}
        responses.append(response)
        client = Mock()
        client.post_res.return_value = response
        return client

    http = Mock(side_effect=transport)
    monkeypatch.setattr("app.modules.slack.slack.RequestUtils", http)
    created = await service.create_connection(ChannelConnectionCreate(
        name="工作区 Slack", provider="slack", provider_config={
            "SLACK_OAUTH_TOKEN": "xoxb-original", "SLACK_APP_TOKEN": "socket-fixture",
        },
    ))
    assert created.can_rotate_credential
    before = service.read()
    del accounts["xoxb-original"]

    for secret in ("xoxb-other-team", "xoxb-other-bot"):
        with pytest.raises(ChannelSettingsConflict, match="另一个平台账号"):
            await service.rotate_credential(created.id, ChannelCredentialRotation.model_validate({
                "secret": secret, "expected_revision": created.revision,
            }))
        assert service.read() == before
    rotated = await service.rotate_credential(created.id, ChannelCredentialRotation.model_validate({
        "secret": "xoxb-replacement", "expected_revision": created.revision,
    }))
    current = ChannelSettings.model_validate(config.get(SystemConfigKey.ChannelSettings))
    assert rotated.credential_status == "ready" and rotated.revision == created.revision + 1
    assert rotated.identity_namespace == created.identity_namespace
    assert service.read().notifications == before.notifications and service.read().interactions == before.interactions
    assert current.connections[created.id].provider_config == {
        "SLACK_OAUTH_TOKEN": "xoxb-replacement", "SLACK_APP_TOKEN": "socket-fixture",
    }
    assert "T1:B1" not in service.read().model_dump_json()
    assert "xoxb-" not in service.read().model_dump_json()
    assert http.call_count == 4
    assert all(response.close.call_count == 1 for response in responses)




@pytest.mark.asyncio
async def test_credential_rotation_keeps_identity_and_pauses_when_unverifiable(monkeypatch):
    """
    同账号轮换保留功能配置，账号不一致时拒绝，无法核验时暂停实际收发。
    """
    config = _Configuration([{
        "id": "tg", "type": "telegram", "name": "Telegram", "enabled": True,
        "config": {"TELEGRAM_TOKEN": "first-token", "TELEGRAM_CHAT_ID": "member"},
    }])
    from app.modules.telegram import module as telegram_module
    from app.runtime.extensions.service import configure_service_config_reader
    from app.startup.initializers import modules as startup_modules

    clients = []

    class Telegram:
        """
        记录正常模块生命周期启动的平台客户端及其账号配置。
        """

        def __init__(self, **arguments):
            """
            保存模块实际交给客户端的连接配置。
            """
            self.initial_config = arguments
            self.stop = Mock(return_value=True)
            clients.append(self)

    monkeypatch.setattr(telegram_module, "Telegram", Telegram)
    monkeypatch.setattr(startup_modules, "get_configured_system_config", lambda: config)
    previous_reader = configure_service_config_reader(startup_modules._read_service_config)
    module = TelegramModule()
    publish_change = config.async_publish_committed_change

    async def reload_after_commit(key):
        """
        使用真实模块的配置重载回调停止并重建客户端。
        """
        await publish_change(key)
        module.on_config_changed()

    monkeypatch.setattr(config, "async_publish_committed_change", reload_after_commit)
    module.init_module()
    measured: list[str] = []

    async def verify(connection):
        """
        模拟官方返回的账号身份。
        """
        token = connection.provider_config["TELEGRAM_TOKEN"]
        measured.append(token)
        return {"first-token": "10", "second-token": "10", "other-account": "20", "renewed-token": "10"}.get(token)

    service = ChannelSettingsService(config, probe=verify)
    original = service.read()
    assert original.connections[0].can_rotate_credential

    def request(secret, revision):
        """
        构造与前端请求等价的模型。
        """
        return ChannelCredentialRotation.model_validate({"secret": secret, "expected_revision": revision})

    async def rotate(secret, revision):
        """
        执行现有连接的条件写入。
        """
        return await service.rotate_credential("tg", request(secret, revision))

    try:
        rotated = await rotate("second-token", 1)
        assert rotated.identity_namespace == original.connections[0].identity_namespace
        assert rotated.revision == 2 and rotated.credential_status == "ready"
        assert measured == ["first-token", "second-token"]
        assert "second-token" not in service.read().model_dump_json()
        assert service.read().interactions == original.interactions
        assert service.read().notifications == original.notifications
        snapshot = config.get(SystemConfigKey.ChannelSettings)

        with pytest.raises(ChannelSettingsConflict, match="另一个平台账号"):
            await rotate("other-account", 2)
        assert config.get(SystemConfigKey.ChannelSettings) == snapshot
        paused = await rotate("unknown-token", 2)
        assert paused.credential_status == "verification_required" and paused.enabled
        frozen = ChannelSettings.model_validate(config.get(SystemConfigKey.ChannelSettings))
        assert frozen.connections["tg"].provider_config["TELEGRAM_TOKEN"] == "second-token"
        runtime = project_runtime_channels(frozen)[0]
        assert not runtime.enabled and not runtime.notification_enabled and not runtime.interaction_enabled
        assert module.get_instance("Telegram") is None

        with pytest.raises(ChannelSettingsConflict, match="已更新"):
            await rotate("renewed-token", 2)
        resumed = await rotate("renewed-token", 3)
        assert resumed.credential_status == "ready"
        assert measured == ["first-token", "second-token", "other-account", "unknown-token", "renewed-token"]
        assert [client.initial_config["TELEGRAM_TOKEN"] for client in clients] == [
            "first-token", "second-token", "renewed-token",
        ]
        clients[0].stop.assert_called_once()
        clients[1].stop.assert_called_once()
        assert module.get_instance("Telegram") is clients[2]
    finally:
        module.stop()
        configure_service_config_reader(previous_reader)

















@pytest.mark.parametrize(
    "enabled,notify,interact,expected",
    [
        (False, True, True, (False, False, False)),
        (True, False, False, (False, False, False)),
        (True, True, False, (True, True, False)),
        (True, False, True, (True, False, True)),
        (True, True, True, (True, True, True)),
    ],
)
@pytest.mark.asyncio
async def test_shared_client_and_dispatch_obey_independent_switches(monkeypatch, enabled, notify, interact, expected):
    """
    检查运行实例是否活动，并使用模块实际过滤器检查事件通知和交互回复。
    """
    config = _Configuration([{
        "id": "tg", "type": "telegram", "name": "Telegram", "enabled": True,
        "switchs": [MessageType.Agent.value],
    }])
    service = ChannelSettingsService(config)
    await service.edit_notification("tg", NotificationRouteEdit(
        enabled=notify, message_types=(MessageType.Agent.value,), expected_revision=1,
    ))
    await service.edit_interaction("tg", InteractionPolicyEdit(enabled=interact, expected_revision=1))
    await service.edit_connection("tg", ChannelConnectionEdit(name="Telegram", enabled=enabled, expected_revision=1))
    from app.startup.initializers import modules as startup_modules

    monkeypatch.setattr(startup_modules, "get_configured_system_config", lambda: config)
    projected = startup_modules._read_service_config(SystemConfigKey.Notifications)
    (projection,) = [NotificationConf.model_validate(row) for row in projected]
    from app.application.notification import channel_interaction_is_enabled
    from app.runtime.extensions.service import ServiceConfigHelper, configure_service_config_reader

    reader = configure_service_config_reader(startup_modules._read_service_config)
    try:
        assert ServiceConfigHelper.get_notification_configs() == [projection]
        from app.application import notification as notification_application

        monkeypatch.setattr(notification_application, "get_service_configs",
                            lambda key, _: ServiceConfigHelper.get_notification_configs())
        assert channel_interaction_is_enabled(NotificationChannel.Telegram, "Telegram") is expected[2]
        assert not channel_interaction_is_enabled(NotificationChannel.Slack, "Telegram")
    finally:
        configure_service_config_reader(reader)

    module = TelegramModule()
    monkeypatch.setattr(module, "_channel", NotificationChannel.Telegram)
    monkeypatch.setattr(module, "get_config", lambda _: projection)

    event = Message(channel=NotificationChannel.Telegram, source="Telegram", mtype=MessageType.Agent, text="主动通知")
    reply = Message(channel=NotificationChannel.Telegram, source="Telegram", userid="42", delivery_kind="reply", text="搜索结果")
    assert (projection.enabled, module.check_message(event, "Telegram"), module.check_message(reply, "Telegram")) == expected


def test_channel_settings_migration_writes_final_resources(tmp_path, monkeypatch):
    """
    在隔离 SQLite 里重复升级后只保留最终资源，正式版本配置仍能读取。
    """
    import importlib

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    from app.db.models.systemconfig import SystemConfig

    migration = importlib.import_module("database.versions.62c91ad8b057_channel_resources")
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'settings.sqlite'}")
    table = SystemConfig.__table__
    legacy = [{"id": "legacy-tg", "name": "机器人", "type": "telegram"}]
    try:
        table.create(engine)
        with engine.begin() as connection:
            connection.execute(sa.insert(table).values(key=SystemConfigKey.Notifications.value, value=legacy))
            monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(connection)))
            migration._migrate_channel_configuration()
            migration._migrate_channel_configuration()
            values = dict(connection.execute(sa.select(table.c.key, table.c.value)).tuples().all())
            assert values[SystemConfigKey.Notifications.value] == legacy
            current = values[SystemConfigKey.ChannelSettings.value]
            assert current["connections"]["legacy-tg"]["name"] == "机器人"
            assert current["interactions"]["legacy-tg"]["admission"] == "manual"
            assert current["notifications"]["legacy-tg"]["rules"] is not None
            with pytest.raises(RuntimeError, match="备份"):
                migration.downgrade()
    finally:
        engine.dispose()










@pytest.mark.asyncio
async def test_wechat_app_edit_and_rotation_keep_identity_and_hide_credentials(monkeypatch):
    """
    企业微信应用通过真实平台扩展编辑回调和轮换 secret；诊断模拟，公开表单永不回填凭据。
    """
    from app.modules.wechat.channel import WechatPlatform
    platform = WechatPlatform()
    source = _Configuration([{
        "id": "corp", "name": "corp", "type": "wechat", "enabled": True, "switchs": ["订阅"],
        "config": {"WECHAT_MODE": "app", "WECHAT_CORPID": "fixture-corp", "WECHAT_APP_ID": "3",
                   "WECHAT_APP_SECRET": "fixture-old", "WECHAT_TOKEN": "callback-token", "WECHAT_ENCODING_AESKEY": "callback-key"},
    }])
    verify = Mock(side_effect=lambda _corp, _agent, secret: "fixture-account" if secret in {"fixture-old", "fixture-new"} else "other-account")
    monkeypatch.setattr("app.modules.wechat.wechat.WeChat.probe_app_identity", verify)

    async def probe(connection):
        """
        使用实际模块诊断逻辑，外部 API 替身保持身份比较行为。
        """
        return platform.probe_identity(connection)

    service = ChannelSettingsService(source, probe=probe)
    original, = service.read().connections
    assert original.can_rotate_credential
    form = service.read_connection_form("corp")
    assert set(form.editable_fields) == {"WECHAT_TOKEN", "WECHAT_ENCODING_AESKEY"}
    assert not {"WECHAT_TOKEN", "WECHAT_ENCODING_AESKEY", "WECHAT_APP_SECRET"}.intersection(form.values)
    edited = await service.edit_connection("corp", ChannelConnectionEdit(
        name="corp", enabled=True, expected_revision=1,
        provider_config={"WECHAT_TOKEN": "", "WECHAT_ENCODING_AESKEY": "replacement-callback-key"},
    ))
    snapshot = source.state[SystemConfigKey.ChannelSettings]
    assert snapshot["connections"]["corp"]["provider_config"]["WECHAT_TOKEN"] == "callback-token"
    assert edited.identity_namespace == original.identity_namespace
    with pytest.raises(ValueError):
        await service.edit_connection("corp", ChannelConnectionEdit(
            name="corp", enabled=True, expected_revision=2, provider_config={"WECHAT_CORPID": "replacement-corp"},
        ))
    rotated = await service.rotate_credential("corp", ChannelCredentialRotation(secret="fixture-new", expected_revision=2))
    assert rotated.revision == 3 and rotated.identity_namespace == original.identity_namespace
    verify.assert_any_call("fixture-corp", "3", "fixture-new")
    with pytest.raises(ChannelSettingsConflict, match="另一个平台账号"):
        await service.rotate_credential("corp", ChannelCredentialRotation(secret="fixture-foreign", expected_revision=3))
    for address in ("@all", "alice|bob"):
        with pytest.raises(ValueError, match="单个企业微信"):
            await service.edit_notification("corp", NotificationRouteEdit(
                enabled=True, expected_revision=1,
                rules=({"kind": "user", "target": address, "message_types": ["订阅"]},),
            ))
    assert source.state[SystemConfigKey.ChannelSettings]["connections"]["corp"]["provider_config"]["WECHAT_APP_SECRET"] == "fixture-new"
