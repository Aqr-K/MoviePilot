from pathlib import Path
from unittest.mock import patch

from app.agent.tools.impl.transfer_file import TransferFileTool


def test_transfer_file_local_directory_without_trailing_slash_uses_dir(tmp_path):
    """本地目录路径即使没有尾斜杠，也应按目录交给整理链路。"""
    source_dir = tmp_path / "Movie Folder"
    source_dir.mkdir()
    captured = {}

    def _manual_transfer(self, **kwargs):
        """记录工具传给整理链路的参数。"""
        captured.update(kwargs)
        return True, None

    with patch(
        "app.chain.transfer.TransferChain.manual_transfer",
        new=_manual_transfer,
    ):
        result = TransferFileTool._transfer_file_sync(str(source_dir))

    assert result == f"整理成功：{source_dir}"
    assert captured["fileitem"].type == "dir"
    assert captured["fileitem"].path == str(source_dir)


def test_transfer_file_local_file_uses_file(tmp_path):
    """本地文件路径应继续按文件交给整理链路。"""
    source_file = tmp_path / "Movie.mkv"
    source_file.write_text("fake media", encoding="utf-8")
    captured = {}

    def _manual_transfer(self, **kwargs):
        """记录工具传给整理链路的参数。"""
        captured.update(kwargs)
        return True, None

    with patch(
        "app.chain.transfer.TransferChain.manual_transfer",
        new=_manual_transfer,
    ):
        result = TransferFileTool._transfer_file_sync(str(source_file))

    assert result == f"整理成功：{source_file}"
    assert captured["fileitem"].type == "file"
    assert captured["fileitem"].path == str(source_file)


def test_transfer_file_remote_directory_still_uses_trailing_slash():
    """远程存储无法用本地 stat 判断时，继续使用尾斜杠识别目录。"""
    captured = {}

    def _manual_transfer(self, **kwargs):
        """记录工具传给整理链路的参数。"""
        captured.update(kwargs)
        return True, None

    with patch(
        "app.chain.transfer.TransferChain.manual_transfer",
        new=_manual_transfer,
    ):
        result = TransferFileTool._transfer_file_sync(
            "downloads/Show/",
            storage="alist",
        )

    assert result == "整理成功：/downloads/Show/"
    assert captured["fileitem"].type == "dir"
    assert captured["fileitem"].path == "/downloads/Show/"
