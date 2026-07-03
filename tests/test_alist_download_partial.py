"""
Alist.download 下载失败返回残缺文件回归测试（H4）。

流式写盘中途异常时，原实现 `if local_path.exists(): return local_path` 把已写入的
部分字节文件当成功返回；transhandler 不校验大小即 move 入库、move 模式随后删源，
造成媒体库落入截断文件 + 源不可恢复丢失（Alist 是唯一失败仍返回路径的后端）。
修复：失败时删除部分文件并返回 None；仅流循环正常结束才返回路径。
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from app.modules.filemanager.storages import alist as alist_module
from app.modules.filemanager.storages.alist import Alist
from app.schemas import FileItem


class _FakeGetResp:
    status_code = 200

    @staticmethod
    def json():
        return {"code": 200, "message": "success",
                "data": {"raw_url": "http://openlist.test/raw/movie.mp4", "sign": ""}}

    def __bool__(self):
        return True


class _StreamCtx:
    """模拟 request_utils.get_stream(...) 的流式响应上下文管理器。"""

    def __init__(self, chunks, fail_after=None):
        self._chunks = chunks
        self._fail_after = fail_after

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=8192):
        for i, c in enumerate(self._chunks):
            if self._fail_after is not None and i >= self._fail_after:
                raise IOError("connection reset mid-stream")
            yield c


def _run_download(stream_ctx, dest: Path):
    storage = Alist()
    fileitem = FileItem(storage="alist", type="file", path="/movie.mp4", name="movie.mp4")
    request_utils = MagicMock()
    request_utils.post_res.return_value = _FakeGetResp()
    request_utils.get_stream.return_value = stream_ctx
    with patch.object(Alist, "get_conf",
                      return_value={"url": "http://openlist.test", "token": "tok"}), \
         patch.object(storage, "_Alist__get_header_with_token", return_value={}), \
         patch.object(alist_module, "RequestUtils", return_value=request_utils):
        result = storage.download(fileitem, path=dest)
    return result, dest / "movie.mp4"


def test_download_failure_removes_partial_and_returns_none():
    with TemporaryDirectory() as d:
        dest = Path(d)
        # 先写 chunk0（b"AAAA"）后在 chunk1 抛异常，local_path 留下部分字节
        result, local_path = _run_download(
            _StreamCtx([b"AAAA", b"BBBB", b"CCCC"], fail_after=1), dest
        )
        assert result is None, "失败下载必须返回 None，不得返回残缺文件路径"
        assert not local_path.exists(), "失败下载的部分文件必须被清理"


def test_download_success_returns_full_file():
    with TemporaryDirectory() as d:
        dest = Path(d)
        result, local_path = _run_download(
            _StreamCtx([b"AAAA", b"BBBB", b"CCCC"], fail_after=None), dest
        )
        assert result == local_path
        assert local_path.read_bytes() == b"AAAABBBBCCCC"
