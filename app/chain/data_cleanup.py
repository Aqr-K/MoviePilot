import json
from datetime import datetime, timedelta
from typing import Callable, Optional, Dict, Any

from sqlalchemy.orm import Session

from app.db import SessionFactory
from app.db.models.downloadhistory import DownloadHistory, DownloadFiles
from app.db.models.message import Message
from app.db.models.siteuserdata import SiteUserData
from app.db.models.transferhistory import TransferHistory
from app.log import logger


class DataCleanupChain:
    """
    系统数据清理链。
    """

    DEFAULT_BATCH_SIZE = 500
    MESSAGE_RETENTION_DAYS = 90
    DOWNLOAD_HISTORY_RETENTION_DAYS = 180
    SITE_USERDATA_RETENTION_DAYS = 180
    TRANSFER_HISTORY_RETENTION_DAYS = 365 * 3

    def cleanup(self, batch_size: Optional[int] = None) -> Dict[str, Any]:
        """
        按预设保留期执行分批清理。
        """
        started_at = datetime.now()
        batch_size = batch_size or self.DEFAULT_BATCH_SIZE
        if batch_size <= 0:
            batch_size = self.DEFAULT_BATCH_SIZE

        message_cutoff = (
            started_at - timedelta(days=self.MESSAGE_RETENTION_DAYS)
        ).strftime("%Y-%m-%d %H:%M:%S")
        download_history_cutoff = (
            started_at - timedelta(days=self.DOWNLOAD_HISTORY_RETENTION_DAYS)
        ).strftime("%Y-%m-%d %H:%M:%S")
        site_userdata_cutoff = (
            started_at - timedelta(days=self.SITE_USERDATA_RETENTION_DAYS)
        ).strftime("%Y-%m-%d")
        transfer_history_cutoff = (
            started_at - timedelta(days=self.TRANSFER_HISTORY_RETENTION_DAYS)
        ).strftime("%Y-%m-%d %H:%M:%S")

        report: Dict[str, Any] = {
            "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "batch_size": batch_size,
            "tables": {},
            "total_deleted": 0,
        }
        errors = []

        plans = [
            {
                "name": "message",
                "cutoff": message_cutoff,
                "handler": lambda db: Message.delete_before(
                    db=db,
                    before_time=message_cutoff,
                    limit=batch_size,
                ),
            },
            {
                "name": "downloadhistory",
                "cutoff": download_history_cutoff,
                "handler": lambda db: DownloadHistory.delete_before(
                    db=db,
                    before_time=download_history_cutoff,
                    limit=batch_size,
                ),
            },
            {
                "name": "downloadfiles",
                "cutoff": "follow-parent-history",
                "handler": lambda db: DownloadFiles.delete_orphans(
                    db=db,
                    limit=batch_size,
                ),
            },
            {
                "name": "siteuserdata",
                "cutoff": site_userdata_cutoff,
                "handler": lambda db: SiteUserData.delete_before(
                    db=db,
                    before_day=site_userdata_cutoff,
                    limit=batch_size,
                ),
            },
            {
                "name": "transferhistory",
                "cutoff": transfer_history_cutoff,
                "handler": lambda db: TransferHistory.delete_before(
                    db=db,
                    before_time=transfer_history_cutoff,
                    limit=batch_size,
                ),
            },
        ]

        with SessionFactory() as db:
            for plan in plans:
                name = plan["name"]
                try:
                    table_report = self._cleanup_in_batches(
                        db=db,
                        table_name=name,
                        delete_batch=plan["handler"],
                    )
                    table_report["cutoff"] = plan["cutoff"]
                    report["tables"][name] = table_report
                    report["total_deleted"] += table_report["deleted"]
                except Exception as err:
                    errors.append(f"{name}: {str(err)}")
                    logger.error(f"数据表 {name} 清理失败：{str(err)}")
                    report["tables"][name] = {
                        "deleted": 0,
                        "batches": 0,
                        "cutoff": plan["cutoff"],
                        "error": str(err),
                    }

        if errors:
            report["errors"] = errors
            logger.error(
                f"数据表清理部分失败：{json.dumps(report, ensure_ascii=False)}"
            )
            raise RuntimeError("；".join(errors))

        logger.info(f"数据表清理完成：{json.dumps(report, ensure_ascii=False)}")
        return report

    @staticmethod
    def _cleanup_in_batches(
        db: Session,
        table_name: str,
        delete_batch: Callable[[Session], int],
    ) -> Dict[str, int]:
        """
        循环执行单表分批删除，直到没有可删除数据。
        """
        total_deleted = 0
        batches = 0

        while True:
            deleted = delete_batch(db) or 0
            if deleted <= 0:
                break
            batches += 1
            total_deleted += deleted
            logger.info(
                f"数据表 {table_name} 清理第 {batches} 批完成，删除 {deleted} 条记录"
            )

        return {
            "deleted": total_deleted,
            "batches": batches,
        }
