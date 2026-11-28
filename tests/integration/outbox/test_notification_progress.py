"""
Outbox 分段进度的真实数据库认领栅栏和正式升级回归。
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.application.messaging.delivery import merge_notification_progress
from app.application.outbox import DOWNLOAD_NOTIFICATION_TOPIC, OutboxIntent, OutboxLeaseLostError
from app.db.adapters.outbox import SqlAlchemyOutboxDispatchStore, SqlAlchemyOutboxStager
from app.db.models.outbox import OutboxMessage
from app.schemas.delivery import DeliveryResult
from app.schemas.types import NotificationChannel


def test_notification_progress_is_fenced_by_claim_and_preserves_confirmed_part(tmp_path) -> None:
    """
    部分投递记录在恢复后可读取，旧认领不能覆盖当前进度。
    """
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'notification.db'}")
    OutboxMessage.__table__.create(engine)
    factory = sessionmaker(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    event_key = "notification:fixture"
    with factory.begin() as session:
        SqlAlchemyOutboxStager(session).stage(OutboxIntent(
            event_key=event_key, topic=DOWNLOAD_NOTIFICATION_TOPIC, payload={"message": {"title": "测试"}},
        ), now)

    store = SqlAlchemyOutboxDispatchStore(factory)
    first = store.claim_by_event_key(event_key, now, now + timedelta(seconds=1))
    assert first is not None
    success = DeliveryResult(channel=NotificationChannel.Wechat, connection_id="corp",
                             identity_namespace="bot", target_id="group:one", part=0, status="confirmed")
    unknown = success.model_copy(update={"part": 1, "status": "unknown"})
    store.update_notification_progress(first, lambda snapshot: (
        None, merge_notification_progress(snapshot, (success, unknown)),
    ))

    later = now + timedelta(seconds=2)
    second = store.claim_by_event_key(event_key, later, later + timedelta(seconds=10))
    assert second is not None
    with pytest.raises(OutboxLeaseLostError):
        store.update_notification_progress(first, lambda _: (None, {}))
    failure = success.model_copy(update={"status": "retryable_failure"})
    store.update_notification_progress(second, lambda snapshot: (
        None, merge_notification_progress(snapshot, (failure,)),
    ))
    with factory() as session:
        row = session.scalars(select(OutboxMessage)).one()
        assert row.payload == {"message": {"title": "测试"}, "idempotency_key": event_key}
        assert row.notification_progress is not None
        assert {(part["part"], part["status"]) for part in row.notification_progress.values()} == {
            (0, "confirmed"), (1, "unknown"),
        }
    engine.dispose()



def test_notification_progress_migration_preserves_legacy_intent_and_guards_downgrade(tmp_path) -> None:
    """
    已有业务通知迁移后保留，写入进度后需要用备份回退。
    """
    from importlib import import_module

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from pytest import MonkeyPatch

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'legacy-outbox.db'}")
    migration = import_module("database.versions.62c91ad8b057_channel_resources")
    legacy = sa.Table("outboxmessage", sa.MetaData(),
                      sa.Column("id", sa.Integer, primary_key=True),
                      sa.Column("event_key", sa.String, nullable=False))
    try:
        with engine.begin() as connection, MonkeyPatch.context() as patch:
            legacy.create(connection)
            connection.execute(legacy.insert().values(id=1, event_key="example-event"))
            patch.setattr(migration, "op", Operations(MigrationContext.configure(connection)))
            migration._add_notification_progress()
            migration._add_notification_progress()
            current = sa.Table("outboxmessage", sa.MetaData(), autoload_with=connection)
            assert connection.execute(sa.select(current)).one() == (1, "example-event", None)
            with pytest.raises(RuntimeError, match="备份"):
                migration.downgrade()
            migration._add_notification_progress()
            connection.execute(current.update().values(notification_progress={"part": {"status": "confirmed"}}))
            with pytest.raises(RuntimeError, match="备份"):
                migration.downgrade()
    finally:
        engine.dispose()
