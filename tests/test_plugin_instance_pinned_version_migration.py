"""插件实例版本绑定列的 Alembic 迁移测试。"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION_MODULE = "database.versions.c5b9e3a71f48_3_0_39"


def _bind_migration(monkeypatch, connection):
    """把迁移绑定到隔离数据库连接。"""
    migration = importlib.import_module(MIGRATION_MODULE)
    context = MigrationContext.configure(connection)
    monkeypatch.setattr(migration, "op", Operations(context))
    return migration


def _create_legacy_table(connection: sa.engine.Connection) -> None:
    """建出加列之前的实例表结构，并写入本体与分身各一行。"""
    now = datetime.now(timezone.utc).isoformat()
    table = sa.Table(
        "plugininstance",
        sa.MetaData(),
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.String(length=128), nullable=False),
        sa.Column("source_plugin_id", sa.String(length=128), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
    )
    table.create(connection)
    connection.execute(
        table.insert(),
        [
            {
                "instance_id": "DemoPlugin",
                "source_plugin_id": "DemoPlugin",
                "is_enabled": True,
                "created_at": now,
                "updated_at": now,
            },
            {
                "instance_id": "DemoPluginWork",
                "source_plugin_id": "DemoPlugin",
                "is_enabled": True,
                "created_at": now,
                "updated_at": now,
            },
        ],
    )


def _columns(connection: sa.engine.Connection) -> set:
    """读取实例表当前列名。"""
    return {column["name"] for column in sa.inspect(connection).get_columns("plugininstance")}


def _pinned_versions(connection: sa.engine.Connection) -> dict:
    """按实例 ID 读取版本绑定列。"""
    return {
        row[0]: row[1]
        for row in connection.execute(
            sa.text("SELECT instance_id, pinned_version FROM plugininstance")
        ).fetchall()
    }


def test_upgrade_adds_the_column_and_leaves_every_row_following_current(monkeypatch):
    """升级只加列不回填：升级这一刻没有任何用户钉过版本，全部实例仍跟随当前版本。"""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        _create_legacy_table(connection)
        migration = _bind_migration(monkeypatch, connection)

        migration.upgrade()

        assert "pinned_version" in _columns(connection)
        assert _pinned_versions(connection) == {
            "DemoPlugin": None,
            "DemoPluginWork": None,
        }


def test_upgrade_is_idempotent_on_repeated_run(monkeypatch):
    """全新库由 create_all 建出当前模型后再跑迁移不得因列已存在而失败。"""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        _create_legacy_table(connection)
        migration = _bind_migration(monkeypatch, connection)

        migration.upgrade()
        migration.upgrade()

        assert "pinned_version" in _columns(connection)


def test_upgrade_is_a_noop_when_the_table_does_not_exist(monkeypatch):
    """实例表尚未建出时升级退化为空操作，而不是抛出中断整条迁移链。"""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        migration = _bind_migration(monkeypatch, connection)

        migration.upgrade()

        assert "plugininstance" not in set(sa.inspect(connection).get_table_names())


def test_downgrade_drops_the_column_and_keeps_the_other_settings(monkeypatch):
    """回滚只删版本绑定列，行本身与其它设置原样保留。"""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        _create_legacy_table(connection)
        migration = _bind_migration(monkeypatch, connection)
        migration.upgrade()
        connection.execute(
            sa.text(
                "UPDATE plugininstance SET pinned_version = :version "
                "WHERE instance_id = :instance_id"
            ),
            {"version": "1.0.0", "instance_id": "DemoPluginWork"},
        )

        migration.downgrade()

        assert "pinned_version" not in _columns(connection)
        rows = {
            row[0]: row[1]
            for row in connection.execute(
                sa.text("SELECT instance_id, source_plugin_id FROM plugininstance")
            ).fetchall()
        }
        assert rows == {"DemoPlugin": "DemoPlugin", "DemoPluginWork": "DemoPlugin"}


def test_downgrade_is_idempotent_on_repeated_run(monkeypatch):
    """重复回滚不得因列已删除而失败。"""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        _create_legacy_table(connection)
        migration = _bind_migration(monkeypatch, connection)
        migration.upgrade()

        migration.downgrade()
        migration.downgrade()

        assert "pinned_version" not in _columns(connection)
