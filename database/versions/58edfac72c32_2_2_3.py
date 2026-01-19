"""2.2.3
添加 downloadhistory.custom_words 字段，用于整理时应用订阅识别词

Revision ID: 58edfac72c32
Revises: 41ef1dd7467c
Create Date: 2026-01-19
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "58edfac72c32"
down_revision = "41ef1dd7467c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 检查并添加 downloadhistory.custom_words
    dh_columns = inspector.get_columns('downloadhistory')
    if not any(c['name'] == 'custom_words' for c in dh_columns):
        op.add_column('downloadhistory', sa.Column('custom_words', sa.String, nullable=True))


def downgrade() -> None:
    # 降级时删除字段
    op.drop_column('downloadhistory', 'custom_words')
