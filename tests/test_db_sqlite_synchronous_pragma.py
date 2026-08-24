"""
SQLite `PRAGMA synchronous` 的连接级配置测试。

synchronous 是会话状态，不随库文件持久化，sqlite3 驱动每建立一条新的物理连接都会
重置为默认的 FULL（每次 commit 都 fsync）。仓库此前只在引擎构建时设过一次
journal_mode，从未设置过 synchronous，因此实际一直跑在 FULL——WAL + NORMAL 才是
标准组合。这里验证：同步/异步引擎都能按配置应用该值、每条新连接都生效（而不是
只在引擎构建时生效一次）、非法配置值有安全回退、PostgreSQL 路径完全不受影响。
"""
import asyncio

import pytest
from sqlalchemy import NullPool, text

from app.runtime.config import settings
from app.db import engine as engine_module


# PRAGMA synchronous 的整数编码：0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
_SYNCHRONOUS_CODES = {"OFF": 0, "NORMAL": 1, "FULL": 2, "EXTRA": 3}


@pytest.fixture
def _dispose_sync_engine():
    """用例结束后释放本用例自建的同步引擎，避免连接泄漏到后续用例。"""
    built = []
    yield built
    for engine in built:
        engine.dispose()


@pytest.mark.parametrize("level", ["OFF", "NORMAL", "FULL", "EXTRA"])
def test_sqlite_sync_engine_applies_configured_synchronous(
        monkeypatch, _dispose_sync_engine, level):
    """同步 SQLite 引擎的每条新连接都应应用配置的 synchronous 级别。"""
    monkeypatch.setattr(settings, "DB_SYNCHRONOUS", level, raising=False)

    engine = engine_module.build_sqlite_engine("sqlite:///:memory:")
    _dispose_sync_engine.append(engine)

    with engine.connect() as connection:
        actual = connection.execute(text("PRAGMA synchronous")).scalar()

    assert actual == _SYNCHRONOUS_CODES[level]


def test_sqlite_sync_engine_applies_pragma_to_every_new_physical_connection(
        monkeypatch, _dispose_sync_engine):
    """
    必须挂在 connect 事件上逐连接设置，不能只在引擎构建时生效一次。

    用 NullPool 强制每次 checkout 都新建物理连接，两次都必须看到配置生效，
    这才证明监听的是 connect 事件而不是构建期的一次性 PRAGMA。
    """
    monkeypatch.setattr(settings, "DB_SYNCHRONOUS", "OFF", raising=False)
    monkeypatch.setattr(settings, "DB_POOL_TYPE", "NullPool", raising=False)

    engine = engine_module.build_sqlite_engine("sqlite:///:memory:")
    _dispose_sync_engine.append(engine)
    assert isinstance(engine.pool, NullPool)

    for _ in range(2):
        with engine.connect() as connection:
            actual = connection.execute(text("PRAGMA synchronous")).scalar()
            assert actual == _SYNCHRONOUS_CODES["OFF"]


def test_sqlite_async_engine_applies_configured_synchronous(monkeypatch):
    """异步 SQLite 引擎（aiosqlite）也必须应用同一份 synchronous 配置。"""
    monkeypatch.setattr(settings, "DB_SYNCHRONOUS", "OFF", raising=False)

    async def run():
        async_engine = engine_module._get_sqlite_engine(is_async=True)
        try:
            async with async_engine.connect() as connection:
                return (await connection.execute(text("PRAGMA synchronous"))).scalar()
        finally:
            await async_engine.dispose()

    actual = asyncio.run(run())
    assert actual == _SYNCHRONOUS_CODES["OFF"]


def test_invalid_synchronous_value_falls_back_to_normal_with_warning(
        monkeypatch, _dispose_sync_engine):
    """非法配置值不得让引擎构建失败，须回退 NORMAL 并留下告警日志。"""
    monkeypatch.setattr(settings, "DB_SYNCHRONOUS", "TURBO", raising=False)
    warnings = []
    monkeypatch.setattr(engine_module.logger, "warn", warnings.append)

    engine = engine_module.build_sqlite_engine("sqlite:///:memory:")
    _dispose_sync_engine.append(engine)

    with engine.connect() as connection:
        actual = connection.execute(text("PRAGMA synchronous")).scalar()

    assert actual == _SYNCHRONOUS_CODES["NORMAL"]
    assert warnings, "非法配置值必须记录告警"
    assert "TURBO" in warnings[0]


def test_default_synchronous_is_normal():
    """默认值应为 NORMAL——WAL + NORMAL 是标准组合，而不是保留 SQLite 默认的 FULL。"""
    assert settings.DB_SYNCHRONOUS == "NORMAL"


def test_postgresql_engine_build_does_not_register_sqlite_pragma(monkeypatch):
    """
    PostgreSQL 路径完全不受影响：既不应调用 SQLite 的 pragma 注册函数，
    也不应在 connect_args 或引擎参数里出现 synchronous 相关内容。
    """
    from unittest.mock import MagicMock

    called = []
    monkeypatch.setattr(engine_module, "_register_sqlite_synchronous_pragma",
                        lambda *_a, **_kw: called.append(1))
    monkeypatch.setattr(engine_module, "create_engine", lambda **_kw: MagicMock())
    monkeypatch.setattr(engine_module, "_register_database_error_logging", lambda *_a: None)

    engine_module._get_postgresql_engine(is_async=False)

    assert not called, "PostgreSQL 引擎构建不应触碰 SQLite 的 synchronous 注册"


def test_postgresql_async_engine_build_does_not_register_sqlite_pragma(monkeypatch):
    """PostgreSQL 异步引擎构建同样不受 SQLite synchronous 配置影响。"""
    from unittest.mock import MagicMock

    called = []
    monkeypatch.setattr(engine_module, "_register_sqlite_synchronous_pragma",
                        lambda *_a, **_kw: called.append(1))
    monkeypatch.setattr(engine_module, "create_async_engine",
                        lambda **_kw: MagicMock(sync_engine=MagicMock()))
    monkeypatch.setattr(engine_module, "_register_database_error_logging", lambda *_a: None)

    engine_module._get_postgresql_engine(is_async=True, pooled=False)

    assert not called, "PostgreSQL 异步引擎构建不应触碰 SQLite 的 synchronous 注册"


# --------------------------------------------------------------------------- #
# check_same_thread 与 WAL 开关解耦（正交的两件事）
# --------------------------------------------------------------------------- #

def test_check_same_thread_disabled_when_wal_disabled(monkeypatch):
    """
    关闭 WAL 后 check_same_thread 依旧必须是 False。

    连接池会跨线程复用连接，这与 journal 模式无关；此前该参数只在 DB_WAL_ENABLE
    为真时才设置，关闭 WAL 后连接跨线程传递会被 sqlite3 驱动的线程校验直接拒绝。
    """
    monkeypatch.setattr(settings, "DB_WAL_ENABLE", False, raising=False)

    assert engine_module._sqlite_connect_args()["check_same_thread"] is False


def test_check_same_thread_disabled_when_wal_enabled(monkeypatch):
    """开启 WAL 时的既有行为不能回退。"""
    monkeypatch.setattr(settings, "DB_WAL_ENABLE", True, raising=False)

    assert engine_module._sqlite_connect_args()["check_same_thread"] is False


def test_connect_args_can_still_override_check_same_thread(monkeypatch):
    """部署侧仍可通过 DB_CONNECT_ARGS 显式覆盖驱动级参数，保留原有的注入能力。"""
    monkeypatch.setattr(settings, "DB_CONNECT_ARGS", {"check_same_thread": True}, raising=False)

    assert engine_module._sqlite_connect_args()["check_same_thread"] is True
