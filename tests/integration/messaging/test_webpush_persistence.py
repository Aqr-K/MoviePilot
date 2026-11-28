"""
浏览器订阅的稳定归属、版本竞争、持久化恢复及失效账号隔离。
"""

import importlib
from functools import partial

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import sessionmaker

from app.application.webpush import WebPushConflictError, WebPushService
from app.db.adapters.webpush import webpush_scope
from app.db.models.user import User
from app.db.models.webpush import WebPushSubscription as SubscriptionRow
from tests.support.messaging.webpush import subscription as _subscription
from tests.support.messaging.webpush import subscription_scope


@pytest.fixture
def browser_devices(tmp_path, monkeypatch):
    """
    为本文件创建并回收独立浏览器设备数据库。

    :param tmp_path: 本用例独立目录
    :param monkeypatch: 自动恢复服务装配
    :yields: 服务与账号身份快照
    """
    yield from subscription_scope(tmp_path, monkeypatch)



def test_accounts_are_isolated_and_service_restart_preserves_subscriptions(browser_devices):
    """
    同账号多设备与 Bob 隔离，重建服务后依然读取数据库登记。

    :param browser_devices: 当前用例独立服务和账号
    """
    case = browser_devices
    alice, owner, bob, bob_owner = case.identities
    case.service.register(alice, _subscription())
    case.service.register(alice, _subscription("two"))
    case.service.register(bob, _subscription("bob"))
    restarted = WebPushService(partial(webpush_scope, case.factory))
    assert {item.endpoint for item in restarted.for_owners((owner,))} == {
        "https://push.example/one", "https://push.example/two",
    }
    assert len(restarted.for_owners((bob_owner,))) == 1
    assert len(restarted.management_targets()) == 3
    assert restarted.for_owners(()) == ()
    assert all(set(item.subscription()) == {"endpoint", "keys"} for item in restarted.management_targets())



def test_endpoint_reassignment_requires_full_existing_keys_and_stale_cleanup_is_safe(browser_devices):
    """
    换号须持有完整旧密钥；旧账号撤销和旧 410 失败不能删除新账号登记。

    :param browser_devices: 当前用例独立服务和账号
    """
    service = browser_devices.service
    alice, owner, bob, bob_owner = browser_devices.identities
    sub = _subscription()
    service.register(alice, sub)
    old = service.for_owners((owner,))[0]
    assert service.is_current(old)
    with pytest.raises(WebPushConflictError):
        service.register(bob, _subscription(auth="forged-secret"))
    assert len(service.for_owners((owner,))) == 1
    service.register(bob, sub)
    assert not service.is_current(old)
    service.unregister(alice, sub)
    assert not service.remove_expired(old)
    assert service.for_owners((owner,)) == ()
    current = service.for_owners((bob_owner,))[0]
    service.register(bob, sub)
    assert not service.remove_expired(current)
    latest = service.for_owners((bob_owner,))[0]
    assert service.remove_expired(latest)
    assert service.for_owners((bob_owner,)) == ()



@pytest.mark.parametrize("state", ["disabled", "channel", "deleted", "recreated"])
def test_unavailable_accounts_never_receive_or_register_devices(browser_devices, state):
    """
    停用、内部账号、删除和同主键重建均不能继承旧订阅。

    :param browser_devices: 当前用例独立服务和账号
    :param state: 本次要验证的账号状态变化
    """
    case = browser_devices
    alice, owner, _, _ = case.identities
    case.service.register(alice, _subscription())
    with case.factory.begin() as session:
        user = session.get(User, alice)
        if state == "disabled":
            user.is_active = False
        elif state == "channel":
            user.account_type = "channel"
        else:
            session.delete(user)
            session.flush()
            if state == "recreated":
                session.add(User(id=alice, name="alice", is_active=True, account_type="local"))
    assert case.service.for_owners((owner,)) == ()
    assert case.service.management_targets() == ()
    if state != "recreated":
        with pytest.raises(PermissionError):
            case.service.register(alice, _subscription("new"))



def test_account_rename_preserves_ownership_and_self_unsubscribe_is_idempotent(browser_devices):
    """
    改名不改变归属，本人主动取消及重复取消都不残留设备。

    :param browser_devices: 当前用例独立服务和账号
    """
    case = browser_devices
    alice, owner, _, _ = case.identities
    case.service.register(alice, _subscription())
    with case.factory.begin() as session:
        session.get(User, alice).name = "renamed"
    assert len(case.service.for_owners((owner,))) == 1
    case.service.unregister(alice, _subscription())
    case.service.unregister(alice, _subscription())
    assert case.service.for_owners((owner,)) == ()



def test_migration_is_repeatable_and_does_not_claim_legacy_records(tmp_path, monkeypatch):
    """
    新迁移重复升级不重复建表、不推断 owner，建出的真实表支持服务登记。

    :param tmp_path: 本次用例的独立数据库路径
    :param monkeypatch: 恢复 Alembic 操作上下文
    """
    migration = importlib.import_module("database.versions.62c91ad8b057_channel_resources")
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'migration.sqlite'}")
    User.__table__.create(engine)
    try:
        with engine.begin() as connection:
            monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(connection)))
            migration._create_browser_devices()
            migration._create_browser_devices()
            assert connection.scalar(sa.select(sa.func.count()).select_from(SubscriptionRow.__table__)) == 0
        factory = sessionmaker(engine)
        with factory.begin() as session:
            user = User(name="migrated", is_active=True, account_type="local")
            session.add(user)
            session.flush()
            user_id = user.id
        service = WebPushService(partial(webpush_scope, factory))
        service.register(user_id, _subscription())
        assert len(service.management_targets()) == 1
    finally:
        engine.dispose()
