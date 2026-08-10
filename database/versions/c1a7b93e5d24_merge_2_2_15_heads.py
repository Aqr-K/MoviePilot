"""2.2.15
合并并行产生的两个迁移分支

上游的 a8c4e2f6b1d9（下载历史海报字段）与本地的 7f5c1d2e3a4b（整理历史按源
存储与源路径唯一）都以 f7b2d5c9a301 为父，形成了两个 head，`alembic upgrade
head` 会因 "Multiple head revisions are present" 直接失败，导致此后任何新迁移
都无法应用。这里做一次纯拓扑合并，不改变任何表结构。

Revision ID: c1a7b93e5d24
Revises: a8c4e2f6b1d9, 7f5c1d2e3a4b
Create Date: 2026-08-10
"""

revision = "c1a7b93e5d24"
down_revision = ("a8c4e2f6b1d9", "7f5c1d2e3a4b")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    纯合并修订：两个分支各自的表结构变更已经完成，此处无需任何操作。
    """
    pass


def downgrade() -> None:
    """
    纯合并修订：回滚时同样无需任何操作。
    """
    pass
