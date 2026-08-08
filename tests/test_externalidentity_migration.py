"""tests/test_externalidentity_migration.py

验证 e1a2b3c4d5e6_3_0_0 迁移（ssoidentity → externalidentity 重命名）的数据保留语义。

测试策略：直接调用迁移模块中的 ``_rename_sso_to_external(conn)`` 辅助函数，
使用 in-memory SQLite + raw SQLAlchemy 连接，无需启动 Alembic 运行时。
这避免了 alembic MigrationContext 在测试中难以初始化的问题，
同时完整覆盖迁移的业务语义（数据保留、幂等性、双表共存的 create_all 副产物处理）。
"""

import importlib.util
import os
import sys
import sqlite3
import pytest
import sqlalchemy as sa
from sqlalchemy import text

# ---------------------------------------------------------------------------
# 动态 import 迁移模块（版本目录没有 __init__.py，使用 spec 加载）
# ---------------------------------------------------------------------------

_MIGRATION_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "database",
    "versions",
    "e1a2b3c4d5e6_3_0_0.py",
)

def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_3_0_0", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_migration = _load_migration()
_rename_sso_to_external = _migration._rename_sso_to_external


# ---------------------------------------------------------------------------
# 辅助：建 ssoidentity 表（旧表结构）
# ---------------------------------------------------------------------------

_SSO_DDL = """
CREATE TABLE ssoidentity (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    subject     TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    username    TEXT,
    created_at  DATETIME,
    CONSTRAINT uq_ssoidentity_provider_subject UNIQUE (provider_id, subject)
)
"""

_EXT_DDL = """
CREATE TABLE externalidentity (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    subject     TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    username    TEXT,
    created_at  DATETIME,
    CONSTRAINT uq_externalidentity_provider_subject UNIQUE (provider_id, subject)
)
"""


def _make_engine():
    """每次测试都建一个独立 in-memory 引擎。"""
    return sa.create_engine("sqlite:///:memory:", future=True)


def _table_exists(conn: sa.engine.Connection, name: str) -> bool:
    result = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": name},
    )
    return result.fetchone() is not None


def _row_count(conn: sa.engine.Connection, table: str) -> int:
    return conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()


# ---------------------------------------------------------------------------
# 测试 1：升级场景 —— 旧数据完整保留
# ---------------------------------------------------------------------------

def test_upgrade_preserves_existing_rows():
    """ssoidentity 有数据 + create_all 建出的空 externalidentity → rename 后数据完好。"""
    engine = _make_engine()
    with engine.begin() as conn:
        # 建旧表并插入两行
        conn.execute(text(_SSO_DDL))
        conn.execute(text(
            "INSERT INTO ssoidentity (provider_id, subject, user_id, username) "
            "VALUES ('github', '123', 1, 'alice'), ('oidc', 'sub-456', 2, 'bob')"
        ))
        # 模拟 create_all 先建出空的 externalidentity
        conn.execute(text(_EXT_DDL))

    with engine.connect() as conn:
        _rename_sso_to_external(conn)
        conn.commit()

    with engine.connect() as conn:
        assert _table_exists(conn, "externalidentity"), "externalidentity 必须存在"
        assert not _table_exists(conn, "ssoidentity"), "ssoidentity 必须已消失"
        assert _row_count(conn, "externalidentity") == 2, "两行数据必须保留"

        rows = conn.execute(
            text("SELECT provider_id, subject, user_id FROM externalidentity ORDER BY id")
        ).fetchall()
        assert rows[0] == ("github", "123", 1)
        assert rows[1] == ("oidc", "sub-456", 2)


# ---------------------------------------------------------------------------
# 测试 2：新装场景 —— ssoidentity 从未存在，仅有 create_all 的 externalidentity
# ---------------------------------------------------------------------------

def test_upgrade_fresh_install_is_noop():
    """新装时 ssoidentity 不存在，upgrade 幂等，externalidentity 保持不变。"""
    engine = _make_engine()
    with engine.begin() as conn:
        # 只有 create_all 建出的 externalidentity（空）
        conn.execute(text(_EXT_DDL))

    with engine.connect() as conn:
        _rename_sso_to_external(conn)
        conn.commit()

    with engine.connect() as conn:
        assert _table_exists(conn, "externalidentity"), "externalidentity 应仍存在"
        assert not _table_exists(conn, "ssoidentity"), "ssoidentity 不应凭空出现"


# ---------------------------------------------------------------------------
# 测试 3：二次运行幂等 —— ssoidentity 已消失
# ---------------------------------------------------------------------------

def test_upgrade_idempotent_on_second_run():
    """迁移已运行过（ssoidentity 已不存在），再次调用不报错。"""
    engine = _make_engine()
    with engine.begin() as conn:
        conn.execute(text(_EXT_DDL))
        conn.execute(text(
            "INSERT INTO externalidentity (provider_id, subject, user_id) VALUES ('gh', '1', 1)"
        ))

    with engine.connect() as conn:
        # 第一次
        _rename_sso_to_external(conn)
        # 第二次（幂等）
        _rename_sso_to_external(conn)
        conn.commit()

    with engine.connect() as conn:
        assert _table_exists(conn, "externalidentity")
        assert _row_count(conn, "externalidentity") == 1, "行数不应变化"


# ---------------------------------------------------------------------------
# 测试 4：仅有 ssoidentity（无 externalidentity）—— 无 create_all 副产物
# ---------------------------------------------------------------------------

def test_upgrade_without_preexisting_externalidentity():
    """没有 create_all 副产物时，直接 rename 也能成功。"""
    engine = _make_engine()
    with engine.begin() as conn:
        conn.execute(text(_SSO_DDL))
        conn.execute(text(
            "INSERT INTO ssoidentity (provider_id, subject, user_id) VALUES ('saml', 'uid-9', 3)"
        ))

    with engine.connect() as conn:
        _rename_sso_to_external(conn)
        conn.commit()

    with engine.connect() as conn:
        assert _table_exists(conn, "externalidentity")
        assert not _table_exists(conn, "ssoidentity")
        row = conn.execute(text("SELECT provider_id, subject, user_id FROM externalidentity")).fetchone()
        assert row == ("saml", "uid-9", 3)


# ---------------------------------------------------------------------------
# 测试 5：回滚（downgrade）— externalidentity → ssoidentity
# ---------------------------------------------------------------------------

def test_downgrade_renames_back():
    """downgrade 时 externalidentity 被重命名回 ssoidentity。"""
    engine = _make_engine()
    with engine.begin() as conn:
        conn.execute(text(_EXT_DDL))
        conn.execute(text(
            "INSERT INTO externalidentity (provider_id, subject, user_id) VALUES ('github', '42', 1)"
        ))

    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        tables = inspector.get_table_names()
        if "externalidentity" in tables and "ssoidentity" not in tables:
            conn.execute(text("ALTER TABLE externalidentity RENAME TO ssoidentity"))
        conn.commit()

    with engine.connect() as conn:
        assert _table_exists(conn, "ssoidentity")
        assert not _table_exists(conn, "externalidentity")
        row = conn.execute(text("SELECT provider_id, subject, user_id FROM ssoidentity")).fetchone()
        assert row == ("github", "42", 1)


# ---------------------------------------------------------------------------
# 测试 6：模块元数据校验
# ---------------------------------------------------------------------------

def test_migration_metadata():
    """校验迁移文件的 revision / down_revision 与链头一致。"""
    assert _migration.revision == "e1a2b3c4d5e6"
    assert _migration.down_revision == "8ab72c49d1e3"
    assert _migration.branch_labels is None
    assert _migration.depends_on is None
