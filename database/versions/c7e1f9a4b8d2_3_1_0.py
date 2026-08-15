"""3.1.0
新增插件实例配置表

Revision ID: c7e1f9a4b8d2
Revises: f4c8d2a7b1e6
Create Date: 2026-08-15
"""

from alembic import op
import sqlalchemy as sa


revision = "c7e1f9a4b8d2"
down_revision = "f4c8d2a7b1e6"
branch_labels = None
depends_on = None


def _inspector() -> sa.Inspector:
    """返回使用当前迁移连接的数据库检查器。"""
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    """检查表是否存在。"""
    return table_name in _inspector().get_table_names()


def upgrade() -> None:
    """建立插件实例配置表，以 (instance_id, plugin_id) 唯一确定一条配置。"""
    if _has_table("pluginconfig"):
        return
    op.create_table(
        "pluginconfig",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("instance_id", sa.String(), nullable=False),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("log_level", sa.String(), nullable=True),
        sa.Column("log_expires_at", sa.DateTime(), nullable=True),
        sa.Column("config_data", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("instance_id", "plugin_id", name="uk_instance_plugin"),
    )


def downgrade() -> None:
    """回退插件实例配置表；表中仍有配置时拒绝执行。"""
    if not _has_table("pluginconfig"):
        return
    pluginconfig = sa.table("pluginconfig", sa.column("id", sa.Integer))
    remaining = op.get_bind().execute(
        sa.select(pluginconfig.c.id).limit(1)
    ).first()
    if remaining:
        raise RuntimeError(
            "pluginconfig 表中仍有插件配置，删表会直接丢数据。"
            "请先降级到 d1a5c8e3f7b2 之前把配置写回 systemconfig，再回退本迁移。"
        )
    op.drop_table("pluginconfig")
