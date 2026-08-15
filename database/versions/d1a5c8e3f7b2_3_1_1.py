"""3.1.1
插件配置迁移到插件实例配置表

Revision ID: d1a5c8e3f7b2
Revises: c7e1f9a4b8d2
Create Date: 2026-08-15
"""

from datetime import datetime

from alembic import op
import sqlalchemy as sa


revision = "d1a5c8e3f7b2"
down_revision = "c7e1f9a4b8d2"
branch_labels = None
depends_on = None

# 插件配置在系统配置表中的键前缀
LEGACY_KEY_PREFIX = "plugin."

# 插件未创建分身时使用的主实例标识
DEFAULT_INSTANCE_ID = "default"


def _inspector() -> sa.Inspector:
    """返回使用当前迁移连接的数据库检查器。"""
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    """检查表是否存在。"""
    return table_name in _inspector().get_table_names()


def _systemconfig_table() -> sa.TableClause:
    """构造迁移期使用的系统配置表引用。"""
    return sa.table(
        "systemconfig",
        sa.column("id", sa.Integer),
        sa.column("key", sa.String),
        sa.column("value", sa.JSON),
    )


def _pluginconfig_table() -> sa.TableClause:
    """构造迁移期使用的插件实例配置表引用。"""
    return sa.table(
        "pluginconfig",
        sa.column("instance_id", sa.String),
        sa.column("plugin_id", sa.String),
        sa.column("is_enabled", sa.Boolean),
        sa.column("config_data", sa.JSON),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )


def _derive_enabled(config) -> bool:
    """
    从插件配置中判定启用状态

    enable 与 enabled 两种拼写都识别，前者优先；两者都不存在时视为未启用。
    """
    if not isinstance(config, dict):
        return False
    if "enable" in config:
        return bool(config.get("enable"))
    if "enabled" in config:
        return bool(config.get("enabled"))
    return False


def upgrade() -> None:
    """把系统配置表中的插件配置搬到插件实例配置表，并清除原键。"""
    if not _has_table("systemconfig") or not _has_table("pluginconfig"):
        return

    connection = op.get_bind()
    systemconfig = _systemconfig_table()
    pluginconfig = _pluginconfig_table()

    legacy_rows = connection.execute(
        sa.select(systemconfig.c.id, systemconfig.c.key, systemconfig.c.value).where(
            systemconfig.c.key.like(f"{LEGACY_KEY_PREFIX}%")
        )
    ).fetchall()
    if not legacy_rows:
        return

    existing_plugin_ids = set(
        connection.execute(
            sa.select(pluginconfig.c.plugin_id).where(
                pluginconfig.c.instance_id == DEFAULT_INSTANCE_ID
            )
        ).scalars()
    )

    migrated_ids = []
    now = datetime.now()
    for row_id, key, value in legacy_rows:
        plugin_id = key[len(LEGACY_KEY_PREFIX):]
        if not plugin_id:
            continue
        migrated_ids.append(row_id)
        if plugin_id in existing_plugin_ids:
            continue
        connection.execute(
            sa.insert(pluginconfig).values(
                instance_id=DEFAULT_INSTANCE_ID,
                plugin_id=plugin_id,
                is_enabled=_derive_enabled(value),
                config_data=value,
                created_at=now,
                updated_at=now,
            )
        )
        existing_plugin_ids.add(plugin_id)

    if migrated_ids:
        connection.execute(
            sa.delete(systemconfig).where(systemconfig.c.id.in_(migrated_ids))
        )


def downgrade() -> None:
    """把默认实例的插件配置写回系统配置表，并清除实例配置。"""
    if not _has_table("systemconfig") or not _has_table("pluginconfig"):
        return

    connection = op.get_bind()
    systemconfig = _systemconfig_table()
    pluginconfig = _pluginconfig_table()

    rows = connection.execute(
        sa.select(pluginconfig.c.plugin_id, pluginconfig.c.config_data).where(
            pluginconfig.c.instance_id == DEFAULT_INSTANCE_ID
        )
    ).fetchall()
    for plugin_id, config_data in rows:
        key = f"{LEGACY_KEY_PREFIX}{plugin_id}"
        exists = connection.execute(
            sa.select(systemconfig.c.id).where(systemconfig.c.key == key)
        ).first()
        if exists:
            continue
        connection.execute(
            sa.insert(systemconfig).values(key=key, value=config_data)
        )
    connection.execute(
        sa.delete(pluginconfig).where(pluginconfig.c.instance_id == DEFAULT_INSTANCE_ID)
    )
