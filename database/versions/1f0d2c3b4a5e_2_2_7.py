"""2.2.7
为电视剧洗版增加全集整包开关

Revision ID: 1f0d2c3b4a5e
Revises: 9caa49cb3e10
Create Date: 2026-05-13
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "1f0d2c3b4a5e"
down_revision = "9caa49cb3e10"
branch_labels = None
depends_on = None


def _has_column(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    if table_name not in inspector.get_table_names():
        return False
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribe", "best_version_full") is False:
        op.add_column("subscribe", sa.Column("best_version_full", sa.Integer(), nullable=True, server_default="0"))

    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribehistory", "best_version_full") is False:
        op.add_column("subscribehistory", sa.Column("best_version_full", sa.Integer(), nullable=True, server_default="0"))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribehistory", "best_version_full"):
        op.drop_column("subscribehistory", "best_version_full")

    inspector = sa.inspect(op.get_bind())
    if _has_column(inspector, "subscribe", "best_version_full"):
        op.drop_column("subscribe", "best_version_full")
