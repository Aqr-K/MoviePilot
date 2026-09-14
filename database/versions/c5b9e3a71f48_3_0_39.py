"""3.0.39 插件实例增加版本绑定列。

Revision ID: c5b9e3a71f48
Revises: b7d1e4a9c206
Create Date: 2026-09-14
"""

import sqlalchemy as sa
from alembic import op

revision = "c5b9e3a71f48"
down_revision = "b7d1e4a9c206"
branch_labels = None
depends_on = None

_TABLE = "plugininstance"


def _column_names(connection) -> set:
    """读取实例表已有列名；表不存在时为空集。

    表可能尚未建出（全新库由 create_all 先建、或本表迁移链更早的一环被跳过），
    直接 inspect 会抛；返回空集让升级与回滚都退化为空操作。
    """
    inspector = sa.inspect(connection)
    if _TABLE not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    """加上版本绑定列，存量行一律为空即跟随插件当前版本。

    不回填任何值：这一列表达的是「用户把这个实例钉在哪个版本上」，升级这一刻没有
    任何用户做过这个选择，凭空写一个版本号会把全部存量实例从「跟随当前版本」静默
    改成「永远停在升级时那个版本」，此后插件升级对它们一概不生效。列可空正是这个
    事实的正确表示。

    判空后再加列而不是无条件 add_column：全新库由 ``Base.metadata.create_all``
    按当前模型建出时列已经在了，无条件加会在 stamp 之后的重复升级上直接报错。
    """
    columns = _column_names(op.get_bind())
    if not columns:
        return
    if "pinned_version" not in columns:
        op.add_column(
            _TABLE,
            sa.Column("pinned_version", sa.String(length=64), nullable=True),
        )


def downgrade() -> None:
    """删除版本绑定列；绑定事实随之丢弃，全部实例回落到跟随插件当前版本。

    旧结构没有任何一列能承载这个事实，因而只能丢弃而不是搬去别处——搬进业务参数
    会让插件自己的配置里多出一个它不认识的键。
    """
    if "pinned_version" in _column_names(op.get_bind()):
        op.drop_column(_TABLE, "pinned_version")
