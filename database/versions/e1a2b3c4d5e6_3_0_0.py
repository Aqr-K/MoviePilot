"""3.0.0
将 SSO 身份绑定表从 ssoidentity 重命名为 externalidentity。

Revision ID: e1a2b3c4d5e6
Revises: 8ab72c49d1e3
Create Date: 2026-06-26

迁移说明
--------
- 将旧表 ``ssoidentity`` 原样重命名为 ``externalidentity``，保留全部行数据。
- 安全/幂等性：
  * 新装：``ssoidentity`` 从未存在 → 直接跳过，无副作用。
  * 升级：``init_db()`` 在 ``update_db()`` 之前运行（见 app/main.py:107-109），
    因此 ``create_all`` 会先建出一张**空的** ``externalidentity`` 表；
    本迁移检测到此情况后先删除该空表，再执行 rename，确保旧 SSO 绑定行不丢失。
  * 二次运行：``ssoidentity`` 已不存在 → 跳过，无副作用。
- 约束名称说明：SQLite 不支持对现有约束做可移植的原地改名（需重建表）；
  rename_table 会原样保留 ``uq_ssoidentity_provider_subject`` 的约束定义，
  但其业务语义（``provider_id``, ``subject`` 唯一）不变，登录解析逻辑不受影响。
  PostgreSQL 用户可在此迁移后追加 ``op.execute(ALTER CONSTRAINT ...)`` 改名（可选）。
- 下行兼容：``(provider_id, subject)`` 二元组是唯一解析键，
  遗留 ``sso_*`` / ``ext_*`` 派生用户名均通过该键定位，不受表名变更影响。
"""

from alembic import op
import sqlalchemy as sa

revision = "e1a2b3c4d5e6"
down_revision = "8ab72c49d1e3"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    """检查数据表是否已存在。"""
    return table_name in inspector.get_table_names()


def _rename_sso_to_external(conn: sa.engine.Connection) -> None:
    """将 ssoidentity → externalidentity（可测试的纯逻辑函数）。

    Args:
        conn: 已打开的 SQLAlchemy 连接（或可用于 alembic op 操作的连接）。

    Side-effects:
        - 若 ssoidentity 存在且 externalidentity 也存在（create_all 副产物），
          先 DROP externalidentity 再 RENAME。
        - 若 ssoidentity 不存在，直接返回（幂等）。
    """
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if "ssoidentity" not in tables:
        # 新装或已迁移 → 幂等跳过
        return

    if "externalidentity" in tables:
        # create_all 建出的空表，先移除以让 rename 带走真实数据
        conn.execute(sa.text("DROP TABLE externalidentity"))

    conn.execute(sa.text("ALTER TABLE ssoidentity RENAME TO externalidentity"))


def upgrade() -> None:
    """升级：ssoidentity → externalidentity。"""
    conn = op.get_bind()
    _rename_sso_to_external(conn)


def downgrade() -> None:
    """回滚：externalidentity → ssoidentity（仅当 ssoidentity 不存在时）。"""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if "externalidentity" in tables and "ssoidentity" not in tables:
        conn.execute(sa.text("ALTER TABLE externalidentity RENAME TO ssoidentity"))
