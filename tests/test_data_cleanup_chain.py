import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.chain.data_cleanup import DataCleanupChain
from app.db import Base
from app.db.models.downloadhistory import DownloadHistory, DownloadFiles
from app.db.models.message import Message
from app.db.models.siteuserdata import SiteUserData
from app.db.models.transferhistory import TransferHistory


class DataCleanupChainTest(unittest.TestCase):
    """
    数据清理链测试。
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "cleanup.db"
        self.engine = create_engine(f"sqlite:///{db_path}")
        self.SessionFactory = sessionmaker(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_cleanup_removes_expired_rows_in_batches(self):
        """
        指定表应按保留期分批删除，并保留仍在有效期内的数据。
        """
        now = datetime.now()
        old_message_time = (now - timedelta(days=120)).strftime("%Y-%m-%d %H:%M:%S")
        keep_message_time = (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        old_download_time = (now - timedelta(days=240)).strftime("%Y-%m-%d %H:%M:%S")
        keep_download_time = (now - timedelta(days=20)).strftime("%Y-%m-%d %H:%M:%S")
        old_site_day = (now - timedelta(days=240)).strftime("%Y-%m-%d")
        keep_site_day = (now - timedelta(days=2)).strftime("%Y-%m-%d")
        old_transfer_time = (now - timedelta(days=365 * 3 + 30)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        keep_transfer_time = (now - timedelta(days=30)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        with self.SessionFactory() as db:
            db.add_all(
                [
                    Message(reg_time=old_message_time, title="old-1"),
                    Message(reg_time=old_message_time, title="old-2"),
                    Message(reg_time=old_message_time, title="old-3"),
                    Message(reg_time=keep_message_time, title="keep"),
                ]
            )
            db.add_all(
                [
                    DownloadHistory(
                        path="/downloads/old-1",
                        type="电影",
                        title="old-1",
                        download_hash="hash-old-1",
                        date=old_download_time,
                    ),
                    DownloadHistory(
                        path="/downloads/old-2",
                        type="电影",
                        title="old-2",
                        download_hash="hash-old-2",
                        date=old_download_time,
                    ),
                    DownloadHistory(
                        path="/downloads/keep",
                        type="电影",
                        title="keep",
                        download_hash="hash-keep",
                        date=keep_download_time,
                    ),
                ]
            )
            db.add_all(
                [
                    DownloadFiles(
                        download_hash="hash-old-1",
                        fullpath="/downloads/old-1/file.mkv",
                        savepath="/downloads/old-1",
                        filepath="file.mkv",
                    ),
                    DownloadFiles(
                        download_hash="hash-old-2",
                        fullpath="/downloads/old-2/file.mkv",
                        savepath="/downloads/old-2",
                        filepath="file.mkv",
                    ),
                    DownloadFiles(
                        download_hash="hash-keep",
                        fullpath="/downloads/keep/file.mkv",
                        savepath="/downloads/keep",
                        filepath="file.mkv",
                    ),
                    DownloadFiles(
                        download_hash="hash-orphan",
                        fullpath="/downloads/orphan/file.mkv",
                        savepath="/downloads/orphan",
                        filepath="file.mkv",
                    ),
                ]
            )
            db.add_all(
                [
                    SiteUserData(domain="old-1", name="old-1", updated_day=old_site_day),
                    SiteUserData(domain="old-2", name="old-2", updated_day=old_site_day),
                    SiteUserData(domain="keep", name="keep", updated_day=keep_site_day),
                ]
            )
            db.add_all(
                [
                    TransferHistory(
                        src="/src/old",
                        title="old",
                        date=old_transfer_time,
                    ),
                    TransferHistory(
                        src="/src/keep",
                        title="keep",
                        date=keep_transfer_time,
                    ),
                ]
            )
            db.commit()

        with patch("app.chain.data_cleanup.SessionFactory", self.SessionFactory):
            report = DataCleanupChain().cleanup(batch_size=1)

        self.assertEqual(report["tables"]["message"]["deleted"], 3)
        self.assertEqual(report["tables"]["message"]["batches"], 3)
        self.assertEqual(report["tables"]["downloadhistory"]["deleted"], 2)
        self.assertEqual(report["tables"]["downloadfiles"]["deleted"], 3)
        self.assertEqual(report["tables"]["siteuserdata"]["deleted"], 2)
        self.assertEqual(report["tables"]["transferhistory"]["deleted"], 1)

        with self.SessionFactory() as db:
            self.assertEqual(db.query(Message).count(), 1)
            self.assertEqual(db.query(DownloadHistory).count(), 1)
            self.assertEqual(db.query(DownloadFiles).count(), 1)
            self.assertEqual(db.query(SiteUserData).count(), 1)
            self.assertEqual(db.query(TransferHistory).count(), 1)

            keep_download_file = db.query(DownloadFiles).first()
            self.assertEqual(keep_download_file.download_hash, "hash-keep")

    def test_transferhistory_keeps_boundary_records(self):
        """
        恰好位于保留边界上的整理历史不应被提前清理。
        """
        now = datetime.now()
        cutoff_time = (now - timedelta(days=365 * 3)).strftime("%Y-%m-%d %H:%M:%S")

        with self.SessionFactory() as db:
            db.add(
                TransferHistory(
                    src="/src/boundary",
                    title="boundary",
                    date=cutoff_time,
                )
            )
            db.commit()

        with patch("app.chain.data_cleanup.SessionFactory", self.SessionFactory):
            report = DataCleanupChain().cleanup(batch_size=10)

        self.assertEqual(report["tables"]["transferhistory"]["deleted"], 0)

        with self.SessionFactory() as db:
            self.assertEqual(db.query(TransferHistory).count(), 1)
