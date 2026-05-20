import unittest
from unittest.mock import patch

from app.core.event import EventManager
from app.schemas import FileItem, TransferInfo
from app.schemas.types import EventType


class EventTransferNormalizationTest(unittest.TestCase):
    def test_transfer_event_fills_missing_target_items_before_dispatch(self):
        """
        整理事件投递给插件前，应补齐可读取 path 的目标文件和目标目录项。
        """
        event_manager = EventManager()
        transferinfo = TransferInfo(
            success=True,
            fileitem=FileItem(
                storage="alist",
                path="/downloads/Test.Show.S01E01.mkv",
                type="file",
                name="Test.Show.S01E01.mkv",
                size=1024,
            ),
            file_list_new=[
                "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"
            ],
            transfer_type="move",
        )
        event_data = {"transferinfo": transferinfo}

        with patch.object(
                event_manager, "_EventManager__trigger_broadcast_event"
        ):
            event_manager.send_event(EventType.TransferComplete, event_data)

        self.assertIsNotNone(transferinfo.target_item)
        self.assertIsNotNone(transferinfo.target_diritem)
        self.assertEqual(
            "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv",
            transferinfo.target_item.path,
        )
        self.assertEqual(
            "/library/Test Show (2026)/Season 1",
            transferinfo.target_diritem.path,
        )
        self.assertEqual("alist", transferinfo.target_item.storage)
        self.assertEqual("alist", transferinfo.target_diritem.storage)

    def test_transfer_event_fills_missing_target_diritem_from_target_item(self):
        """
        目标文件项已存在但目录项缺失时，事件数据应补齐 target_diritem。
        """
        event_manager = EventManager()
        transferinfo = TransferInfo(
            success=True,
            fileitem=FileItem(
                storage="alist",
                path="/downloads/Test.Show.S01E02.mkv",
                type="file",
                name="Test.Show.S01E02.mkv",
            ),
            target_item=FileItem(
                storage="alist",
                path="/library/Test Show (2026)/Season 1/Test.Show.S01E02.mkv",
                type="file",
                name="Test.Show.S01E02.mkv",
            ),
            file_list_new=[
                "/library/Test Show (2026)/Season 1/Test.Show.S01E02.mkv"
            ],
            transfer_type="move",
        )
        event_data = {"transferinfo": transferinfo}

        with patch.object(
                event_manager, "_EventManager__trigger_broadcast_event"
        ):
            event_manager.send_event(EventType.TransferComplete, event_data)

        self.assertIsNotNone(transferinfo.target_diritem)
        self.assertEqual(
            "/library/Test Show (2026)/Season 1",
            transferinfo.target_diritem.path,
        )
        self.assertEqual("alist", transferinfo.target_diritem.storage)


if __name__ == "__main__":
    unittest.main()
