"""
渠道公共类型 SDK、宿主绑定、生命周期封口和旧插件显式入口的安全合同。
"""

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.application.messaging import ingress
from app.application.security import authorization
from app.schemas.channel import InteractionPolicy
from app.schemas.types import NotificationChannel
from app.sdk import channel as sdk
from scripts.architecture.channel_platforms import (
    CHANNEL_SDK_EXPORTS,
    legacy_ingress_violations,
    sdk_source_violations,
)


@pytest.fixture
def ready_ingress(monkeypatch):
    """
    只替换队列边界；真实授权与规则调用链由独立平台共存回归另行覆盖。
    """
    receiver = Mock()
    monkeypatch.setattr(ingress, "_platform_payload_receiver", receiver)
    monkeypatch.setattr(authorization, "get_channel_authorization", lambda: object())
    monkeypatch.setattr(ingress, "runtime_stop_state", SimpleNamespace(is_system_stopped=False))
    return receiver


def _identity():
    """
    返回宿主已装配的合成连接元数据，不含平台凭据。
    """
    return dict(
        source="channel", channel=NotificationChannel.Telegram, connection_id="connection",
        provider="telegram", identity_namespace="namespace", parser_owner="TelegramModule", policy_revision=4,
    )


def test_public_channel_sdk_is_versioned_type_only_and_cannot_inject_proofs():
    """
    类型门面不暴露注册、可信装配或授权引擎；公开 JSON 不能提交私有证明。
    """
    from app.domain.authorization import ChannelActor
    from app.schemas.message import IncomingMessage

    assert sdk.CHANNEL_EXTENSION_API_VERSION == 1
    assert set(sdk.__all__) == CHANNEL_SDK_EXPORTS
    assert sdk.ChannelActor is ChannelActor and sdk.IncomingMessage is IncomingMessage
    for forbidden in (
        "AdmissionProof", "bind_platform_payload", "submit_platform_payload", "configure_platform_payload_receiver",
        "configure_verified_event_claim", "ChannelAuthorizationService", "ChannelPlatformBase", "CapabilityRegistry",
    ):
        assert not hasattr(sdk, forbidden)
    incoming = sdk.IncomingMessage.model_validate({
        "channel": "platform:public-fixture", "userid": "alice", "text": "申请使用",
        "_admission_proof": {"provider": "telegram", "connection_id": "connection"},
    })
    assert incoming._admission_proof is None
    assert sdk.IncomingMessage.model_validate_json(incoming.model_dump_json()).channel == incoming.channel


















@pytest.mark.parametrize(
    "module,symbol",
    [
        ("telegram.telegram", "forward_message_to_host"), ("slack.slack", "forward_message_to_host"),
        ("discord.discord", "async_forward_message_to_host"), ("feishu.feishu", "submit_message_to_host"),
        ("qqbot.qqbot", "submit_message_to_host"), ("wechat.wechatbot", "submit_message_to_host"),
        ("wechatclawbot.wechatclawbot", "forward_message_to_host"),
    ],
)
def test_old_module_helper_imports_resolve_to_explicit_compatibility(module, symbol):
    """
    旧插件导入仍精确解析至单一兼容实现，宿主模块的物理公开表不恢复旧 helper。
    """
    owner = importlib.import_module("app.modules." + module)
    assert symbol not in owner.__dict__
    assert getattr(owner, symbol) is getattr(ingress, symbol)
    assert symbol not in owner.__all__


@pytest.mark.parametrize("source", [
    "from app.application.messaging.ingress import submit_message_to_host as old\nold({}, 'source', submit=pool)",
    "import app.application.messaging.ingress as entry\nalias = entry\nalias.forward_message_to_host({})",
    "from app.application.messaging import ingress as entry\nalias = entry\nalias.async_forward_message_to_host({})",
    "from app.modules.telegram.telegram import forward_message_to_host as relay\nrelay({})",
    "import app.modules.telegram.telegram as client\nalias = client\nalias.forward_message_to_host({})",
    "from app.modules.telegram import telegram as client\nrelay = client.forward_message_to_host\nrelay({})",
    "import app.application.messaging.ingress\napp.application.messaging.ingress.forward_message_to_host({})",
    "import app.application.messaging.ingress as entry\nrelay: object = entry\nrelay.submit_message_to_host({})",
    "from app.sdk._legacy.ingress import forward_message_to_host as relay\nrelay({})",
])
def test_architecture_guard_rejects_host_legacy_ingress_aliases(source):
    """
    旧 helper 的模块和局部别名不能重新成为宿主的入站旁路。
    """
    assert legacy_ingress_violations(source)


@pytest.mark.parametrize("source", [
    "from app.domain.admission import AdmissionProof as Proof",
    "from app.application.messaging.ingress import configure_platform_payload_receiver as register",
    "import app.application.messaging.ingress as entry",
    "from app.application.messaging.ingress import *",
])
def test_architecture_guard_rejects_trusted_sdk_exports(source):
    """
    公共 SDK 不能通过直接、整体或星号导入扩大可信装配面。
    """
    assert sdk_source_violations(source)


def test_architecture_guard_allows_canonical_calls_and_unrelated_names():
    """
    约束按真实来源识别兼容与信任符号，普通业务同名函数不被当作宿主入口。
    """
    assert not legacy_ingress_violations("client.submit_bound_payload(payload)")
    assert not sdk_source_violations("from example import AdmissionProof")






def test_sdk_v1_keeps_the_existing_platform_method_contract():
    """
    第一版固定既有协议方法的参数形状；实现仍是规范端口，而非另一份接口模型。
    """
    import inspect

    expected = {
        "actor": ("self", "value"), "capabilities": ("self", "connection"), "mode": ("self", "config"),
        "editable_fields": ("self", "connection"), "form_values": ("self", "connection"),
        "patch_config": ("self", "connection", "patch"), "credential_key": ("self", "connection"),
        "inbound_token_key": ("self",), "validate_target": ("self", "connection", "rule"),
        "legacy_rules": ("self", "connection", "route"), "target_fields": ("self",),
        "normalize_interaction": ("self", "value"), "runtime_config": ("self", "connection", "policy"),
        "validate_interaction": ("self", "options"), "private_target": ("self", "value"),
        "bound_address": ("self", "message"), "address_message": ("self", "message", "rule"),
        "conversation": ("self", "address"), "attachment_reference": ("self", "kind", "reference"),
        "split_notification": ("self", "parts"), "probe_identity": ("self", "connection"),
        "reconcile": ("self", "previous", "current"), "export_interaction": ("self", "policy"),
        "import_options": ("self", "connection", "policy"), "manage": ("self", "action", "params"),
    }
    methods = {name: tuple(inspect.signature(value).parameters)
               for name, value in vars(sdk.ChannelPlatform).items() if not name.startswith("_") and callable(value)}
    assert methods == expected




def test_wechat_sdk_authentication_and_stop_gate_do_not_use_http(monkeypatch):
    """
    智能机器人只接受本连接认证后发给本机器人的事件，停机后不提交或切换路径。
    """
    from app.modules.wechat.wechatbot import WeChatBot

    monkeypatch.setattr(WeChatBot, "_start_gateway", lambda self: None)
    monkeypatch.setattr(WeChatBot, "_load_known_targets", lambda self: None)
    bound = Mock(return_value=True)
    bot = WeChatBot(WECHAT_BOT_ID="bot", WECHAT_BOT_SECRET="fixture", message_ingress=bound)
    payload = {"body": {"aibotid": "bot", "chattype": "single", "from": {"userid": "alice"},
                        "msgtype": "text", "text": {"content": "申请使用"}}}
    assert bot._forward_to_message_chain(payload) is False
    bot._authenticated.set()
    assert bot._forward_to_message_chain({"body": payload["body"] | {"aibotid": "other"}}) is False
    assert bot._forward_to_message_chain({"body": payload["body"] | {"compat_info": {}}}) is False
    assert bot._forward_to_message_chain(payload) is True
    bot._stop_event.set()
    assert bot._forward_to_message_chain(payload) is False
    bound.assert_called_once()






@pytest.mark.parametrize("module", ["telegram.telegram", "qqbot.qqbot", "wechatclawbot.wechatclawbot"])
def test_old_incidental_channel_type_import_has_an_explicit_compatibility_mapping(module):
    """
    内部不再使用的枚举导入名仍可供旧插件精确解析，且不恢复物理别名。
    """
    owner = importlib.import_module("app.modules." + module)
    assert "NotificationChannel" not in owner.__dict__
    assert owner.NotificationChannel is sdk.NotificationChannel


@pytest.mark.parametrize("source", [
    "from app.application.messaging import ingress as entry",
    "from app.modules.wechat import _AdmissionProof as Proof",
    "from app.startup.initializers.modules import configure_runtime_data_providers",
])
def test_public_sdk_cannot_reexport_internal_trust_modules(source):
    """
    禁止经模块对象、私有导入别名或启动装配公开可信能力。
    """
    assert sdk_source_violations(source)


def test_explicit_legacy_sdk_http_facade_does_not_use_the_trusted_receiver(ready_ingress, monkeypatch):
    """
    旧 SDK 门面保留显式 HTTP 调用与认证头，不借当前可信接收器传递证明。
    """
    legacy = importlib.import_module("app.sdk._legacy.ingress")
    port = SimpleNamespace(post=Mock(return_value=200))
    monkeypatch.setattr(ingress, "_message_ingress_port", port)
    monkeypatch.setattr(ingress, "get_runtime_setting", lambda key: {"PORT": 3000, "API_TOKEN": "fixture-token"}[key])
    assert set(legacy.__all__) == {"forward_message_to_host", "async_forward_message_to_host", "submit_message_to_host"}
    assert not hasattr(legacy, "bind_platform_payload")
    assert legacy.forward_message_to_host({"text": "申请使用"}, "legacy") is True
    port.post.assert_called_once()
    assert port.post.call_args.kwargs["headers"] == {"X-API-KEY": "fixture-token"}
    ready_ingress.assert_not_called()




@pytest.mark.parametrize("accepted", [True, False])
def test_wechat_private_rule_text_is_submitted_once_even_when_rejected(monkeypatch, accepted):
    """
    私聊规则文本提交失败也已消费本次入口选择，不能落入普通私聊分支重复投递。
    """
    from app.modules.wechat.wechatbot import WeChatBot
    from app.schemas.channel import AdmissionRule

    monkeypatch.setattr(WeChatBot, "_start_gateway", lambda self: None)
    monkeypatch.setattr(WeChatBot, "_load_known_targets", lambda self: None)
    policy = InteractionPolicy(
        connection_id="fixture", identity_namespace="fixture", enabled=True, revision=1,
        admission_rules=(AdmissionRule(kind="user", target="alice", scopes=("search",)),),
    )
    bound = Mock(return_value=accepted)
    bot = WeChatBot(
        WECHAT_BOT_ID="bot", WECHAT_BOT_SECRET="fixture", interaction_policy=policy, message_ingress=bound,
    )
    bot._authenticated.set()
    monkeypatch.setattr(bot, "_remember_target", Mock())
    bot._handle_callback_message({"body": {
        "aibotid": "bot", "chattype": "single", "msgid": "event-one", "from": {"userid": "alice"},
        "msgtype": "text", "text": {"content": "申请使用"},
    }})
    bound.assert_called_once()
