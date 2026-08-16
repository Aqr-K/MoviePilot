"""3.1.2
插件数据表增加实例维度

Revision ID: e5f2a9c7b3d1
Revises: d1a5c8e3f7b2
Create Date: 2026-08-15
"""

from alembic import op
import sqlalchemy as sa


revision = "e5f2a9c7b3d1"
down_revision = "d1a5c8e3f7b2"
branch_labels = None
depends_on = None

# 插件未创建分身时使用的主实例标识
DEFAULT_INSTANCE_ID = "default"

# 按插件与键定位数据的旧索引
LEGACY_INDEX_NAME = "ix_plugindata_plugin_id_key"

# 按插件、实例与键定位数据的索引
INSTANCE_INDEX_NAME = "ix_plugindata_plugin_instance_key"


def _inspector() -> sa.Inspector:
    """返回使用当前迁移连接的数据库检查器。"""
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    """检查表是否存在。"""
    return table_name in _inspector().get_table_names()


def _has_column(table_name: str, column_name: str) -> bool:
    """检查表字段是否存在。"""
    if not _has_table(table_name):
        return False
    return column_name in {
        column["name"] for column in _inspector().get_columns(table_name)
    }


def _has_index(table_name: str, index_name: str) -> bool:
    """检查表索引是否存在。"""
    if not _has_table(table_name):
        return False
    return index_name in {
        index.get("name") for index in _inspector().get_indexes(table_name)
    }


def _plugindata_table() -> sa.TableClause:
    """构造迁移期使用的插件数据表引用。"""
    return sa.table(
        "plugindata",
        sa.column("instance_id", sa.String),
    )


def upgrade() -> None:
    """为插件数据补上实例列，老数据一律归入默认实例。"""
    if not _has_table("plugindata"):
        return

    if not _has_column("plugindata", "instance_id"):
        op.add_column(
            "plugindata",
            sa.Column(
                "instance_id",
                sa.String(),
                nullable=False,
                server_default=DEFAULT_INSTANCE_ID,
            ),
        )

    plugindata = _plugindata_table()
    op.get_bind().execute(
        sa.update(plugindata)
        .where(
            sa.or_(
                plugindata.c.instance_id.is_(None),
                plugindata.c.instance_id == "",
            )
        )
        .values(instance_id=DEFAULT_INSTANCE_ID)
    )

    if not _has_index("plugindata", INSTANCE_INDEX_NAME):
        op.create_index(
            INSTANCE_INDEX_NAME,
            "plugindata",
            ["plugin_id", "instance_id", "key"],
        )
    if _has_index("plugindata", LEGACY_INDEX_NAME):
        op.drop_index(LEGACY_INDEX_NAME, table_name="plugindata")


def downgrade() -> None:
    """
    回退实例列并恢复按插件与键定位的索引。

    旧结构以 ``(plugin_id, key)`` 定位一条数据，分身实例的行删列后会与默认实例挤在
    同一个键上，按键读取从此返回任意一条；存在分身数据时中止回退。
    """
    if not _has_table("plugindata"):
        return

    if _has_column("plugindata", "instance_id"):
        plugindata = _plugindata_table()
        clones = op.get_bind().execute(
            sa.select(plugindata.c.instance_id)
            .where(plugindata.c.instance_id != DEFAULT_INSTANCE_ID)
            .distinct()
        ).scalars().all()
        if clones:
            raise RuntimeError(
                f"存在插件分身实例（{'、'.join(clones)}）的数据，删除实例列会让它们与默认实例"
                "共用同一个 (plugin_id, key)。请先清除这些实例的数据，再回退本迁移。"
            )

    if not _has_index("plugindata", LEGACY_INDEX_NAME):
        op.create_index(
            LEGACY_INDEX_NAME,
            "plugindata",
            ["plugin_id", "key"],
        )
    if _has_index("plugindata", INSTANCE_INDEX_NAME):
        op.drop_index(INSTANCE_INDEX_NAME, table_name="plugindata")
    if _has_column("plugindata", "instance_id"):
        op.drop_column("plugindata", "instance_id")
