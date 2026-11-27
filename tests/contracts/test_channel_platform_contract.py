"""
平台扩展模板的凭据保护、规范地址及惰性目录合同，不启动真实平台。
"""

from types import SimpleNamespace

import pytest

from app.application.messaging.channel import platform as contracts
from app.domain.authorization import ChannelActor, channel_actor_ids
from app.modules._base.channel import ChannelPlatformBase
from app.schemas.channel import ChannelConnection, ChannelPlatformCapabilities, InteractionPolicy, NotificationRoute, NotificationRule
from app.schemas.message import Message


class _Platform(ChannelPlatformBase):
    """
    仅用于模板合同的独立协议实现，不注册宿主入口或授予权限。
    """
    provider = "contract-fixture"
    channel = "platform:contract-fixture"
    edit_fields = ("secret", "label", "destination")
    public_fields = frozenset({"account"})
    write_only = frozenset({"secret"})
    default_targets = (("destination", "conversation"),)
    obsolete_fields = frozenset({"old_destination"})
    target_patterns = {"user": r"person-[a-z]+", "conversation": r"room-[a-z]+"}
    topic_key = "topic"
    topic_pattern = r"[1-9][0-9]*"
    username_key = "usernames"
    rotation_key = "secret"
    token_key = "callback"
    bound_targets = (("personal", "user", True),)
    conversation_prefix = "room:"
    private_pattern = r"person-[a-z]+"
    private_forbidden_prefixes = ("room:",)
    all_address = "everyone"
    capabilities_model = ChannelPlatformCapabilities(target_kinds=("bound", "user", "conversation"))


@pytest.fixture
def connection():
    """
    为合同检查提供不带真实凭据的独立连接。
    """
    return ChannelConnection(id="connection", name="Fixture", provider=_Platform.provider, mode="standard", identity_namespace="space", enabled=True, revision=1, provider_config={"account": "account", "secret": "private-fixture", "label": "label", "destination": "room-one", "topic": "09"})


def test_platform_form_does_not_expose_or_replace_protected_identity(connection):
    """
    只有声明的非敏感字段可回填，空凭据不覆盖旧值，受保护身份不能走普通编辑。
    """
    platform = _Platform()
    assert platform.form_values(connection) == {"account": "account", "label": "label"}
    assert platform.patch_config(connection, {"secret": "", "label": "changed"})["secret"] == "private-fixture"
    assert connection.provider_config["label"] == "label"
    with pytest.raises(ValueError):
        platform.patch_config(connection, {"account": "foreign"})
    assert platform.credential_key(connection) == "secret" and platform.inbound_token_key() == "callback"
    assert platform.capabilities(connection).target_kinds == ("bound", "user", "conversation")
    assert platform.mode(connection.provider_config) == "standard"
    runtime = platform.runtime_config(connection, None)
    runtime["secret"] = "modified-copy"
    assert connection.provider_config["secret"] == "private-fixture"


def test_protocol_address_and_personal_constraints_are_separate(connection):
    """
    地址编码保留线程，群目标不能冒充个人，模板本身不授予业务权限。
    """
    platform = _Platform()
    original = Message(text="notice", targets={"personal": "person-alice"})
    rule = NotificationRule(kind="conversation", target="room-one", thread_id="7", message_types=("订阅",))
    platform.validate_target(connection, rule)
    addressed = platform.address_message(original, rule)
    assert addressed.userid == "room:room-one" and addressed.thread_id == "7" and addressed.targets is None
    assert original.targets == {"personal": "person-alice"}
    assert platform.bound_address(original).target == "person-alice"
    assert platform.bound_address(Message()) is None
    for invalid in [rule.model_copy(update={"target": "person-alice"}), rule.model_copy(update={"thread_id": "0"})]:
        with pytest.raises(ValueError):
            platform.validate_target(connection, invalid)
    assert platform.private_target("person-alice") == "person-alice"
    with pytest.raises(PermissionError):
        platform.private_target("room:one")
    assert platform.conversation("room-one") == "room-one"
    assert channel_actor_ids(platform.actor(" person-alice ")) == ("person-alice",)
    with pytest.raises(ValueError):
        channel_actor_ids(ChannelActor("room-one", "group"))
    with pytest.raises(ValueError):
        channel_actor_ids(ChannelActor("", aliases=("person-alice",)))


def test_legacy_target_projection_keeps_priority_and_invalid_target_disabled(connection):
    """
    历史目标转成明确且保守的规则，非法协议地址留待复核。
    """
    platform = _Platform()
    route = NotificationRoute(connection_id=connection.id, identity_namespace="space", enabled=True, revision=1, message_types=("订阅",))
    rules = platform.legacy_rules(connection, route)
    assert [(rule.kind, rule.target, rule.thread_id) for rule in rules] == [("bound", None, None), ("conversation", "room-one", "9")]
    invalid = connection.model_copy(update={"provider_config": {"destination": "invalid", "topic": "bad", "usernames": " alice,bob"}})
    rules = platform.legacy_rules(invalid, route)
    assert rules[0].legacy_usernames == ("bob",) and rules[1].kind == "review" and not rules[1].enabled
    assert ChannelPlatformBase().legacy_rules(connection, route) is None
    empty = connection.model_copy(update={"provider_config": {}})
    assert platform.legacy_rules(empty, route.model_copy(update={"message_types": ()})) == ()


def test_optional_platform_features_are_closed_without_explicit_implementation(connection):
    """
    模板没有诊断、附件解析或管理副作用，平台额外选项必须显式支持。
    """
    platform = _Platform()
    policy = InteractionPolicy(connection_id=connection.id, identity_namespace="space", enabled=True, revision=1)
    assert platform.validate_interaction({}) == {}
    with pytest.raises(ValueError):
        platform.validate_interaction({"unsupported": True})
    assert platform.import_options(connection, policy) is policy
    assert platform.export_interaction(policy) == policy.model_dump()
    assert platform.normalize_interaction({"enabled": None, "obsolete": None}) == {"enabled": None}
    parts = [Message(text="first"), Message(text="second")]
    assert platform.split_notification(parts) == parts
    assert platform.attachment_reference("image", "unknown://image") is None
    assert platform.probe_identity(connection) is None
    assert platform.manage("login", {}) is None
    assert platform.reconcile((), ()) is None


def test_platform_selection_requires_explicit_provider_or_unique_transport(monkeypatch, connection):
    """
    目录只定位协议 owner；共享传输存在歧义时拒绝，不按第一项或标识格式猜测。
    """
    first = _Platform()
    second = _Platform()
    second.provider = "independent-provider"
    entries = (first, second)
    directory = SimpleNamespace(providers=lambda: entries, get=lambda provider: next((entry for entry in entries if entry.provider == provider), None))
    monkeypatch.setattr("app.application.configuration.get_channel_platform_catalog", lambda: directory)
    assert contracts.platform_for_channel(first.channel, provider=first.provider) is first
    assert contracts.resolve_actor_ids(first.channel, "person-alice", provider=first.provider) == ("person-alice",)
    for provider in (None, "missing"):
        with pytest.raises(ValueError):
            contracts.platform_for_channel(first.channel, provider=provider)
    with pytest.raises(ValueError):
        contracts.platform_for_channel("other", provider=first.provider)
    policy = InteractionPolicy(connection_id=connection.id, identity_namespace="space", enabled=True, revision=1, admission="rules", admission_rules=({"kind": "user", "target": " person-alice ", "scopes": ("search",)},))
    assert contracts.normalize_policy_actors(first.provider, policy).admission_rules[0].target == "person-alice"
    assert contracts.normalize_policy_actors("missing", policy) is policy


def test_host_catalog_preserves_owner_and_rejects_duplicate_or_reserved_identity(monkeypatch):
    """
    清单投影固定 owner，未知版本、插件身份、重复 provider 与网页保留入口均被拒绝。
    """
    from dataclasses import replace
    from pathlib import Path

    from app.runtime.capabilities.model import ActivationPolicy, CapabilitySpec, SelectorSpec
    from app.runtime.extensions.module import channel as registry
    from app.runtime.extensions.module.adapter import HOST_MODULE_KIND

    spec = CapabilitySpec(
        schema_version=1, id="ContractModule", kind=HOST_MODULE_KIND,
        entrypoint=__name__ + ":_Platform", activation=ActivationPolicy.WHEN_CONFIGURED,
        metadata={"name": "Fixture", "subtype": _Platform.channel, "channel_extension": __name__ + ":_Platform", "channel_interaction": True, "channel_api_version": 1},
        selector=SelectorSpec("service", {"match_value": _Platform.provider}),
        watch=(), depends_on=(), source=Path(__file__),
    )
    directory = registry.ModuleChannelCatalog(SimpleNamespace(list_specs=lambda: (spec,)))
    entry = directory.get(_Platform.provider)
    assert entry.module_id == "ContractModule" and entry.provider == _Platform.provider
    assert entry.channel == _Platform.channel and entry.actor("person-alice").id == "person-alice"
    assert directory.get("unknown") is None and directory.providers() == (entry,)
    monkeypatch.setattr(registry, "build_host_module_registry", lambda: SimpleNamespace(list_specs=lambda: (spec,)))
    assert registry.build_channel_platform_catalog.__wrapped__().get(_Platform.provider).module_id == spec.id
    with pytest.raises(ValueError, match="重复"):
        registry.ModuleChannelCatalog(SimpleNamespace(list_specs=lambda: (spec, replace(spec, id="OtherModule"))))
    reserved = replace(spec, metadata={**spec.metadata, "subtype": "Web"})
    with pytest.raises(ValueError, match="网页"):
        registry.ModuleChannelCatalog(SimpleNamespace(list_specs=lambda: (reserved,)))
    for changed in (replace(spec, kind="plugin"), replace(spec, metadata={**spec.metadata, "channel_api_version": 2})):
        with pytest.raises(ValueError):
            registry.ModuleChannelPlatform(changed)
    mismatch = replace(spec, metadata={**spec.metadata, "channel_extension": "app.modules._base.channel:ChannelPlatformBase"})
    with pytest.raises(ValueError, match="身份不一致"):
        registry.ModuleChannelPlatform(mismatch).actor("person-alice")
