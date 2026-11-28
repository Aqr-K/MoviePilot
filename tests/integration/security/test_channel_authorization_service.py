"""
规范授权服务与短事务仓储的版本仲裁、归属及批量撤销回归。
"""

from functools import partial

import pytest
from sqlalchemy import delete, select, update

from app.application.security import authorization as authorization_module
from app.application.security.authorization import ChannelAuthorizationService
from app.db.adapters.authorization import authorization_scope
from app.db.adapters.user import TransactionalUserRepository
from app.db.models.authorization import ChannelAuthorization, ChannelBinding, ChannelRuleTaskGrant
from app.db.models.downloadhistory import DownloadHistory
from app.db.models.message import Message as MessageHistory
from app.db.models.outbox import OutboxMessage
from app.db.models.subscribe import Subscribe
from app.db.models.subscribehistory import SubscribeHistory
from app.db.models.user import User
from app.db.session import SessionFactory, async_session_scope
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel


@pytest.fixture
def channel_authorization(db, monkeypatch):
    """
    装配真实临时数据库授权服务，恢复进程服务并清理新增成员、内部账号及消息历史。

    :param db: 共享隔离库的水位清理工具
    :param monkeypatch: 当前用例的配置函数替换工具
    :yields: 授权服务、启用渠道配置及真实用户仓储
    """
    db.watermark(User, OutboxMessage, MessageHistory)
    configs = [
        NotificationConf(id="telegram-a", name="机器人A", type="telegram", enabled=True),
        NotificationConf(id="telegram-b", name="机器人B", type="telegram", enabled=True),
        NotificationConf(id="wechat-a", name="微信A", type="wechatclawbot", enabled=True),
    ]
    monkeypatch.setattr(
        authorization_module, "get_notification_configs", lambda **_: [item for item in configs if item.enabled]
    )
    service = ChannelAuthorizationService(partial(authorization_scope, SessionFactory))
    previous = authorization_module.get_channel_authorization()
    authorization_module.configure_channel_authorization(service)
    with SessionFactory() as session:
        before = set(session.scalars(select(ChannelAuthorization.id)))
    users = TransactionalUserRepository(sync_session=SessionFactory, async_session=async_session_scope)
    try:
        yield service, configs, users
    finally:
        authorization_module.configure_channel_authorization(previous)
        with SessionFactory() as session:
            session.execute(delete(ChannelBinding))
            new_member_ids = select(ChannelAuthorization.id)
            if before:
                new_member_ids = new_member_ids.where(ChannelAuthorization.id.not_in(before))
            session.execute(delete(ChannelRuleTaskGrant).where(ChannelRuleTaskGrant.member_id.in_(new_member_ids)))
            statement = delete(ChannelAuthorization)
            if before:
                statement = statement.where(ChannelAuthorization.id.not_in(before))
            session.execute(statement)
            session.commit()



def _approve(service, source="机器人A", sender_id="42", role="member", scopes=("search", "subscribe", "download")):
    """
    通过真实审批事务批准合成渠道发送者。
    """
    member = service.request(NotificationChannel.Telegram.value, source, sender_id, "测试成员")
    return service.update(member.id, status="approved", role=role, scopes=scopes, reviewer_id=1)



@pytest.mark.parametrize("conflict", [False, True])
def test_binding_moves_exact_business_identity_atomically(channel_authorization, db, conflict):
    """
    关联只迁移该成员自己的稳定归属。目标已有相同订阅时保留旧记录和关联码。
    """
    service, _, users = channel_authorization
    local = db.add(User(name="binding-owner-target", is_active=True))
    member = service.request("Telegram", "机器人A", "42", "成员")
    previous = users.get_by_id(member.user_id)
    assert previous is not None
    media = {"name": "旧订阅", "type": "电影", "media_source": "themoviedb", "media_id": "123"}
    active = db.add(Subscribe(**media, username="更名后的显示名", owner_identity=previous.notification_identity))
    history = db.add(SubscribeHistory(name="历史", username=previous.name, owner_identity=previous.notification_identity))
    download = db.add(DownloadHistory(path="/synthetic/file", type="电影", title="下载", owner_identity=previous.notification_identity))
    legacy = db.add(Subscribe(name="待人工核对", username=previous.name))
    if conflict:
        duplicate = db.add(Subscribe(**media, username=local.name, owner_identity=local.notification_identity))
    code, _ = service.create_binding(local.id)

    if conflict:
        with pytest.raises(ValueError, match="业务归属冲突"):
            service.bind("Telegram", "机器人A", "42", "成员", code)
        with SessionFactory() as session:
            assert session.get(ChannelAuthorization, member.id).user_identity == previous.notification_identity
            assert session.get(Subscribe, active.id).owner_identity == previous.notification_identity
            assert session.get(SubscribeHistory, history.id).owner_identity == previous.notification_identity
            assert session.get(DownloadHistory, download.id).owner_identity == previous.notification_identity
        with SessionFactory() as session, session.begin():
            session.execute(delete(Subscribe).where(Subscribe.id == duplicate.id))

    linked = service.bind("Telegram", "机器人A", "42", "成员", code)
    assert linked.user_identity == local.notification_identity and linked.status == "pending"
    with SessionFactory() as session:
        for model, record in ((Subscribe, active), (SubscribeHistory, history), (DownloadHistory, download)):
            row = session.get(model, record.id)
            assert row.owner_identity == local.notification_identity and row.username == local.name
        legacy_row = session.get(Subscribe, legacy.id)
        assert legacy_row.username == previous.name and legacy_row.owner_identity is None



def test_implicit_channel_source_must_resolve_one_instance(channel_authorization, monkeypatch):
    """
    兼容调用缺少来源名时只接受唯一配置，重复配置不能猜测实例或借旧名单恢复权限。
    """
    from app.application import notification
    from app.application.messaging.channel.admin import matches_channel_admin

    service, configs, _ = channel_authorization
    member = _approve(service, role="admin")
    config = {"TELEGRAM_ADMINS": "42", "TELEGRAM_CHAT_ID": "42"}
    configs[0].config = config
    monkeypatch.setattr(notification, "get_notification_configs", lambda: configs)
    assert matches_channel_admin(NotificationChannel.Telegram, config, None, "42")
    configs[1].config = config.copy()
    assert not matches_channel_admin(NotificationChannel.Telegram, config, "42")
    configs[1].config = {}
    service.update(member.id, status="disabled", role="admin", scopes=(), reviewer_id=1)
    assert not matches_channel_admin(NotificationChannel.Telegram, config, "42")



@pytest.mark.parametrize("status", ["pending", "approved", "rejected", "disabled"])
def test_delete_authorization_requires_confirmation_and_rotates_reapplication_identity(channel_authorization, status):
    """
    全部状态可删，已授权必须确认；旧身份立即失效，重申请不继承授权和账号关联。
    """
    from app.application.security.authorization import ChannelAuthorizationConflict

    service, _, _ = channel_authorization
    member = service.request("Telegram", "机器人A", "delete-42", "待删除成员")
    if status != "pending":
        member = service.update(member.id, status=status, role="member", scopes=("search",), reviewer_id=1)
    if status == "approved":
        with pytest.raises(ValueError, match="再次确认"):
            service.manage_members("delete", ((member.id, member.updated_at),), reviewer_id=1)
        assert service.find("Telegram", "机器人A", "delete-42") is not None
    service.manage_members("delete", ((member.id, member.updated_at),), reviewer_id=1, confirm_approved=status == "approved")
    assert service.find("Telegram", "机器人A", "delete-42") is None
    with pytest.raises(PermissionError):
        service.principal(member.id)
    with SessionFactory() as session:
        assert session.get(User, member.user_id) is not None
    renewed = service.request("Telegram", "机器人A", "delete-42", "重新申请")
    assert renewed.status == "pending" and renewed.id != member.id
    assert renewed.user_identity != member.user_identity and renewed.linked_user_id is None
    with pytest.raises(ChannelAuthorizationConflict):
        service.manage_members("delete", ((member.id, member.updated_at),), reviewer_id=1, confirm_approved=True)
    assert service.find("Telegram", "机器人A", "delete-42").id == renewed.id



@pytest.mark.parametrize("action,status,result", [("approve", "pending", "approved"), ("reject", "pending", "rejected"), ("disable", "approved", "disabled")])
def test_batch_authorization_uses_selected_versions_and_explicit_member_scopes(channel_authorization, action, status, result):
    """
    批量通过仅授予普通成员及明确权限，拒绝和停用保留原角色权限且不影响未选择成员。
    """
    service, _, _ = channel_authorization
    records = [service.request("Telegram", "机器人A", f"batch-{i}", f"成员{i}") for i in range(3)]
    if status == "approved":
        records = [service.update(m.id, status=status, role="admin", scopes=("search",), reviewer_id=1) for m in records]
    changed = service.manage_members(action, tuple((m.id, m.updated_at) for m in records[:2]), reviewer_id=1, scopes=("search", "schedule"))
    assert {member.status for member in changed} == {result}
    for member in changed:
        assert member.role == ("admin" if action == "disable" else "member")
        assert set(member.scopes) == ({"search", "schedule"} if action == "approve" else {"search"} if action == "disable" else {"search", "subscribe", "download"})
    assert service.find("Telegram", "机器人A", "batch-2").status == status



def test_batch_delete_stale_or_unconfirmed_record_rolls_back_all(channel_authorization):
    """
    批次包含过期版本或未确认的已授权成员时，不删除任何记录。
    """
    from app.application.security.authorization import ChannelAuthorizationConflict

    service, _, _ = channel_authorization
    pending = service.request("Telegram", "机器人A", "pending-delete", "待审批")
    approved = _approve(service, sender_id="approved-delete")
    with pytest.raises(ValueError, match="再次确认"):
        service.manage_members("delete", ((pending.id, pending.updated_at), (approved.id, approved.updated_at)), reviewer_id=1)
    changed = service.update(approved.id, status="disabled", role="member", scopes=("search",), reviewer_id=1)
    with pytest.raises(ChannelAuthorizationConflict):
        service.manage_members("delete", ((pending.id, pending.updated_at), (approved.id, approved.updated_at)), reviewer_id=1, confirm_approved=True)
    assert service.find("Telegram", "机器人A", "pending-delete").id == pending.id
    assert service.find("Telegram", "机器人A", "approved-delete").updated_at == changed.updated_at



def test_batch_mutation_cas_conflict_rolls_back_prior_changes_and_receipts(channel_authorization, monkeypatch):
    """
    校验后的第二条记录在提交时发生版本冲突，前一条修改和回执均回滚。
    """
    from app.application.security.authorization import ChannelAuthorizationConflict
    from app.db.oper.authorization import ChannelAuthorizationOper

    service, _, _ = channel_authorization
    records = sorted([service.request("Telegram", "机器人A", f"cas-{i}", "成员") for i in range(2)], key=lambda m: m.id)
    original = ChannelAuthorizationOper.update
    with SessionFactory() as session:
        before = set(session.scalars(select(OutboxMessage.id)))

    def race(oper, member_id, **kwargs):
        """
        在第二次比较更新前制造一次版本变化。
        """
        if member_id == records[1].id:
            oper._session.execute(update(ChannelAuthorization).where(ChannelAuthorization.id == member_id).values(updated_at=records[1].updated_at + 1))
        return original(oper, member_id, **kwargs)

    monkeypatch.setattr(ChannelAuthorizationOper, "update", race)
    with pytest.raises(ChannelAuthorizationConflict):
        service.manage_members("approve", tuple((m.id, m.updated_at) for m in records), reviewer_id=1)
    assert all(service.find("Telegram", "机器人A", f"cas-{i}").status == "pending" for i in range(2))
    with SessionFactory() as session:
        assert set(session.scalars(select(OutboxMessage.id))) == before



def test_delete_removes_rule_grants_and_keeps_historical_business_owner(channel_authorization):
    """
    删除同时移除规则派生授权，旧任务主体停止生效，业务账号仍保留。
    """
    service, _, _ = channel_authorization
    member = _approve(service, sender_id="rule-delete")
    with SessionFactory() as session:
        session.add(ChannelRuleTaskGrant(id="gdeleted", member_id=member.id, member_version=member.updated_at, policy_revision=1, scopes=["schedule"]))
        session.commit()
    service.manage_members("delete", ((member.id, member.updated_at),), reviewer_id=1, confirm_approved=True)
    with SessionFactory() as session:
        assert session.get(ChannelRuleTaskGrant, "gdeleted") is None
        assert session.get(User, member.user_id) is not None
    with pytest.raises(PermissionError):
        service.principal("gdeleted", capability="schedule")



def test_platform_alias_conflict_is_rejected_inside_one_connection_only(channel_authorization):
    """
    平台别名先规范化再查询，冲突拒绝；另一连接的同一原始标识仍独立。
    """
    service, configs, _ = channel_authorization
    configs.extend([
        NotificationConf(id="voce-first", name="Voce First", type="vocechat", enabled=True),
        NotificationConf(id="voce-second", name="Voce Second", type="vocechat", enabled=True),
    ])
    with pytest.raises(ValueError, match="群地址"):
        service.request("VoceChat", "Voce First", "GID#12", "Not a person")
    first = service.request("VoceChat", "Voce First", "12", "First")
    other = service.request("VoceChat", "Voce First", "13", "Other")
    independent = service.request("VoceChat", "Voce Second", "12", "Independent")
    assert first.sender_id == "UID#12" and independent.id != first.id
    assert service.find("VoceChat", "Voce First", "UID#12").id == first.id
    with SessionFactory() as session:
        session.get(ChannelAuthorization, other.id).aliases = ["UID#12"]
        session.commit()
    for operation in (service.find, service.request):
        arguments = ("VoceChat", "Voce First", "12")
        with pytest.raises(ValueError, match="冲突"):
            operation(*arguments, "Conflicted") if operation == service.request else operation(*arguments)
    assert service.find("VoceChat", "Voce Second", "UID#12").id == independent.id


def test_rule_task_grant_and_private_result_stop_after_policy_or_member_revocation(channel_authorization):
    """
    规则授予定时权限只来自当前认证群；冻结主体与私聊结果在改版、撤权后失效。
    """
    import time

    from app.application.security.authorization import scoped_admission
    from app.domain.admission import AdmissionProof
    from app.schemas.channel import AdmissionRule, InteractionPolicy
    from app.schemas.message import Message

    service, configs, _ = channel_authorization
    policy = InteractionPolicy(connection_id="telegram-a", identity_namespace="telegram-a", enabled=True, revision=5, admission="rules", admission_rules=(AdmissionRule(kind="group", target="-100", scopes=("search", "schedule")),))
    configs[0].interaction_policy = policy
    assert service.rule_task_principal("Telegram", "机器人A", "42") is None
    with scoped_admission(AdmissionProof("telegram-a", 5, "42", "-200", time.time() + 60)):
        assert service.rule_task_principal("Telegram", "机器人A", "42") is None
    with scoped_admission(AdmissionProof("telegram-a", 5, "42", "-100", time.time() + 60)):
        user = service.rule_task_principal("Telegram", "机器人A", "42")
        assert service.rule_task_principal("Telegram", "机器人A", "42").authorization_id == user.authorization_id
    assert user.permissions["schedule"] and not user.permissions["download"] and not user.is_superuser
    with pytest.raises(PermissionError):
        service.authorize_operation(user.authorization_id, "download.add")
    result = service.prepare_task_result(Message(title="完成", original_chat_id="-100", thread_id="7"), user.authorization_id, user.id, user.notification_identity)
    assert result.private_delivery and result.userid == "42"
    assert result.original_chat_id is None and result.thread_id is None
    assert "task_recipient" not in result.model_dump_json()
    service.revalidate_task_result(result)
    configs[0].interaction_policy = policy.model_copy(update={"revision": 6})
    with pytest.raises(PermissionError):
        service.revalidate_task_result(result)
    configs[0].interaction_policy = policy
    member = service.find("Telegram", "机器人A", "42")
    service.update(member.id, status="disabled", role="member", scopes=(), reviewer_id=1)
    with pytest.raises(PermissionError):
        service.principal(user.authorization_id, capability="schedule")


def test_receipt_resolves_only_current_approval_and_original_connection_namespace(channel_authorization):
    """
    审批回执绑定审批版本与连接空间；重复审批幂等，过期版本或重建空间不能发送。
    """
    service, configs, _ = channel_authorization
    member = service.request("Telegram", "机器人A", "receipt-42", "Member")
    reviewed = service.update(member.id, status="approved", role="member", scopes=("search",), reviewer_id=1, queue_receipt=True)
    with SessionFactory() as session:
        before = set(session.scalars(select(OutboxMessage.id)))
    assert service.receipt_target(reviewed.id, reviewed.updated_at, "telegram-a", "telegram-a")[0].id == reviewed.id
    assert service.receipt_target(reviewed.id, member.updated_at, "telegram-a", "telegram-a") is None
    assert service.receipt_target(reviewed.id, reviewed.updated_at, "telegram-b", "telegram-b") is None
    repeated = service.update(reviewed.id, status="approved", role="member", scopes=("search",), reviewer_id=1, queue_receipt=True)
    assert repeated.updated_at == reviewed.updated_at
    with SessionFactory() as session:
        assert set(session.scalars(select(OutboxMessage.id))) == before
    configs[0].identity_namespace = "recreated"
    assert service.receipt_target(reviewed.id, reviewed.updated_at, "telegram-a", "telegram-a") is None
