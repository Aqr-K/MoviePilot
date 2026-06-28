"""atomic_session（P1 #46）：多步 @db_update 写入收敛进单一事务，统一提交或回滚。

验证要点：
- 提交路径：块内多次装饰写入在块结束一次性提交，全部可见；
- 回滚路径：块内异常时整体回滚——因 atomic_session 给会话打 ``_atomic_managed`` 标记，
  @db_update 不再各自提交，故此前已执行的写入同被回滚（证明托管标记生效）；
- 兼容性：未处于 atomic_session 时，@db_update 仍按原语义各自提交（默认路径不变）。
"""
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, Engine, SessionFactory, atomic_session


class _AtomicProbe(Base):
    __tablename__ = "_atomic_probe_p1"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, default="")


def _ensure_table() -> None:
    _AtomicProbe.__table__.create(Engine, checkfirst=True)


def _count() -> int:
    with SessionFactory() as s:
        return s.query(_AtomicProbe).count()


def _purge(*ids: int) -> None:
    with SessionFactory() as s:
        for rid in ids:
            obj = s.get(_AtomicProbe, rid)
            if obj is not None:
                s.delete(obj)
        s.commit()


def test_atomic_session_commits_multiple_writes_together():
    """块内两次装饰写入在块结束统一提交，全部可见。"""
    _ensure_table()
    start = _count()
    try:
        with atomic_session() as db:
            _AtomicProbe(id=99001, name="a").create(db)
            _AtomicProbe(id=99002, name="b").create(db)
        assert _count() == start + 2
    finally:
        _purge(99001, 99002)


def test_atomic_session_rolls_back_all_on_exception():
    """块内异常整体回滚；若装饰器在托管会话上仍逐次提交，则首条写入会幸存——断言其不幸存即证明标记生效。"""
    _ensure_table()
    start = _count()
    try:
        with atomic_session() as db:
            _AtomicProbe(id=99003, name="x").create(db)
            raise ValueError("boom")
    except ValueError:
        pass
    try:
        assert _count() == start
    finally:
        _purge(99003)


def test_db_update_outside_atomic_session_still_commits():
    """默认路径不变：未传会话、未处于 atomic_session 时，@db_update 仍自建会话并提交。"""
    _ensure_table()
    start = _count()
    try:
        _AtomicProbe(id=99004, name="c").create()
        assert _count() == start + 1
    finally:
        _purge(99004)
