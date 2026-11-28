"""
已认证上下文的首次接入权限与跨主体、连接、群组和时效拒绝回归。
"""

from contextlib import nullcontext
from dataclasses import replace
from unittest.mock import Mock

import pytest

from app.application.security import authorization
from app.application.security.authorization import ChannelAuthorizationService, ChannelMember, scoped_admission
from app.domain.admission import AdmissionProof
from app.schemas.channel import AdmissionRule, InteractionPolicy
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel


@pytest.fixture
def policy():
    """
    返回一份启用的可信群聊策略。
    """
    return InteractionPolicy(
        connection_id="wecom-admission", identity_namespace="wecom-admission", enabled=True,
        admission="manual_rules", revision=3,
        admission_rules=(AdmissionRule(kind="group", target="allowed-group", scopes=("search",)),),
    )



@pytest.fixture
def proof(policy):
    """
    生成固定时间和发言人的证明。
    """
    return AdmissionProof(policy.connection_id, policy.revision, "alice", "allowed-group", 1030)



@pytest.mark.parametrize("mode", ["group", "user"])
def test_first_use_has_only_event_permissions(monkeypatch, policy, proof, mode):
    """
    未批准成员可搜索，但不能获得下载、定时或平台外的权限。
    """
    if mode == "user":
        policy = policy.model_copy(update={
            "admission": "manual_rules",
            "admission_rules": (AdmissionRule(kind="user", target="alice", scopes=("search",)),),
        })
        proof = replace(proof, conversation=None, private=True)
    member = ChannelMember(
        id="member", notification_id=policy.connection_id, channel=NotificationChannel.Wechat.value,
        sender_id="alice", display_name="Alice", status="pending", role="member", scopes=(), user_id=5,
        user_identity="channel-user", linked_user_id=None, created_at=0, updated_at=0, origin="request",
        reviewed_by=None,
    )
    config = NotificationConf(id=policy.connection_id, name="corp", type="wechat", enabled=True,
                              interaction_policy=policy, interaction_enabled=True)
    store = Mock()
    store.find.return_value = None
    store.request.return_value = member
    store.user.return_value = authorization.UserSnapshot(
        id=5, name="channel-alice", email=None, avatar=None, is_otp=False,
        is_active=True, is_superuser=False, settings={}, permissions={},
        notification_identity=member.user_identity, account_type="channel",
    )
    service = ChannelAuthorizationService(lambda: nullcontext(store))
    monkeypatch.setattr(authorization, "get_notification_configs", lambda: [config])
    monkeypatch.setattr(authorization.time, "time", lambda: 1000)
    channel = NotificationChannel.Wechat.value
    with scoped_admission(proof):
        user = service.resolve_operation(channel, "corp", "alice", "search.torrents")
        assert user.name == "channel-alice" and user.permissions == {"search": True}
        assert user.authorization_id is None and not user.is_superuser
        with pytest.raises(PermissionError):
            service.resolve_operation(channel, "corp", "alice", "download.add")
        with pytest.raises(PermissionError):
            service.principal(member.id, capability="schedule")
    with pytest.raises(PermissionError):
        service.resolve_operation(channel, "corp", "alice", "search.torrents")
    for denied in ("disabled", "rejected"):
        store.find.return_value = replace(member, status=denied)
        with scoped_admission(proof), pytest.raises(PermissionError):
            service.resolve_operation(channel, "corp", "alice", "search.torrents")
    original = store.user.return_value
    linked = replace(original, id=6, name="local-alice", account_type="local")
    store.find.return_value = store.request.return_value = replace(
        member, user_id=linked.id, linked_user_id=linked.id,
    )
    store.user.return_value = linked
    with scoped_admission(proof), pytest.raises(PermissionError, match="关联账号没有"):
        service.resolve_operation(channel, "corp", "alice", "search.torrents")



@pytest.mark.parametrize("mismatch", [
    {"conversation": "other-group"}, {"connection_id": "different-bot"}, {"revision": 2},
    {"sender": "bob"}, {"expires_at": 1000}, {"conversation": None, "private": True},
])
def test_context_proof_must_match_current_event_and_policy(monkeypatch, policy, proof, mismatch):
    """
    跨群、跨连接、改版、换发言人或过期的证明不能复用。
    """
    config = NotificationConf(id=policy.connection_id, name="corp", type="wechat", enabled=True,
                              interaction_policy=policy)
    monkeypatch.setattr(authorization.time, "time", lambda: 1000)
    with scoped_admission(replace(proof, **mismatch)):
        assert not ChannelAuthorizationService(Mock()).context_scopes(config, "alice")
