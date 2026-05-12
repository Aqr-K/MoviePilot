"""2.2.6
为订阅洗版增加按集优先级状态

Revision ID: 9caa49cb3e10
Revises: b8f6e3a1c2d4
Create Date: 2026-05-12
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "9caa49cb3e10"
down_revision = "b8f6e3a1c2d4"
branch_labels = None
depends_on = None


def _has_column(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    if table_name not in inspector.get_table_names():
        return False
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribe", "episode_priority") is False:
        op.add_column("subscribe", sa.Column("episode_priority", sa.JSON(), nullable=True))

    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribehistory", "episode_priority") is False:
        op.add_column("subscribehistory", sa.Column("episode_priority", sa.JSON(), nullable=True))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribehistory", "episode_priority"):
        op.drop_column("subscribehistory", "episode_priority")

    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribe", "episode_priority"):
        op.drop_column("subscribe", "episode_priority")
