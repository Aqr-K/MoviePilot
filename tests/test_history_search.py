import asyncio
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.db.models.downloadhistory import DownloadHistory
from app.db.models.transferhistory import TransferHistory


def _enable_case_sensitive_like(db):
    """让 SQLite 在测试中暴露与 PostgreSQL 一致的 LIKE 大小写敏感问题。"""
    db.execute(text("PRAGMA case_sensitive_like=ON"))


def test_transfer_history_search_is_case_insensitive(tmp_path: Path):
    """整理历史标题和路径搜索应忽略大小写。"""
    engine = create_engine(f"sqlite:///{tmp_path / 'transfer_history.db'}")
    SessionFactory = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    try:
        with SessionFactory() as db:
            _enable_case_sensitive_like(db)
            db.add_all(
                [
                    TransferHistory(
                        src="/downloads/Avatar.Source.mkv",
                        dest="/media/Avatar/Avatar.mkv",
                        title="Avatar",
                        status=True,
                        date="2026-06-01 00:00:00",
                    ),
                    TransferHistory(
                        src="/downloads/Interstellar.mkv",
                        dest="/media/Interstellar/Interstellar.mkv",
                        title="Interstellar",
                        status=True,
                        date="2026-06-02 00:00:00",
                    ),
                ]
            )
            db.commit()

            title_result = TransferHistory.list_by_title(db, "avatar")
            src_result = TransferHistory.list_by_title(db, "avatar.source")
            dest_result = TransferHistory.list_by_title(db, "%avatar.mkv", wildcard=True)
            total = TransferHistory.count_by_title(db, "avatar")

        assert [item.title for item in title_result] == ["Avatar"]
        assert [item.title for item in src_result] == ["Avatar"]
        assert [item.title for item in dest_result] == ["Avatar"]
        assert total == 1
    finally:
        engine.dispose()


def test_download_history_title_search_is_case_insensitive(tmp_path: Path):
    """下载历史标题搜索和计数应忽略大小写。"""

    async def run_case():
        """执行异步下载历史查询断言。"""
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'download_history.db'}")
        SessionFactory = async_sessionmaker(bind=engine)

        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await conn.execute(text("PRAGMA case_sensitive_like=ON"))

            async with SessionFactory() as db:
                db.add_all(
                    [
                        DownloadHistory(
                            path="/downloads/Avatar",
                            type="电影",
                            title="Avatar",
                            date="2026-06-01 00:00:00",
                        ),
                        DownloadHistory(
                            path="/downloads/Interstellar",
                            type="电影",
                            title="Interstellar",
                            date="2026-06-02 00:00:00",
                        ),
                    ]
                )
                await db.commit()

                result = await DownloadHistory.async_list_by_title(db, "avatar")
                total = await DownloadHistory.async_count_by_title(db, "avatar")

            assert [item.title for item in result] == ["Avatar"]
            assert total == 1
        finally:
            await engine.dispose()

    asyncio.run(run_case())
