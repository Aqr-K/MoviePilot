import unittest

from app.schemas import FileItem, TransferInfo


class TransferInfoTest(unittest.TestCase):
    def test_ensure_target_items_fills_missing_target_items_from_target_path(self):
        """
        整理结果只有目标路径清单时，应补齐目标文件项和目录项。
        """
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

        transferinfo.ensure_target_items()

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

    def test_ensure_target_items_keeps_new_model_initial_state(self):
        """
        新建整理结果模型不应立即改写目标项，避免影响失败记录等非事件流程。
        """
        transferinfo = TransferInfo(
            success=True,
            fileitem=FileItem(
                storage="alist",
                path="/downloads/Test.Show.S01E01.mkv",
                type="file",
                name="Test.Show.S01E01.mkv",
            ),
            file_list_new=[
                "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"
            ],
            transfer_type="move",
        )

        self.assertIsNone(transferinfo.target_item)
        self.assertIsNone(transferinfo.target_diritem)

    def test_ensure_target_items_fills_missing_target_diritem_from_target_item(self):
        """
        目标文件项已存在但目录项缺失时，应从目标文件路径推导目录项。
        """
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

        transferinfo.ensure_target_items()

        self.assertIsNotNone(transferinfo.target_diritem)
        self.assertEqual(
            "/library/Test Show (2026)/Season 1",
            transferinfo.target_diritem.path,
        )
        self.assertEqual("alist", transferinfo.target_diritem.storage)


if __name__ == "__main__":
    unittest.main()
