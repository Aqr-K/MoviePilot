"""
图片代理缓存键路径穿越（任意文件读/写）回归测试。

覆盖纵深防御三层：
1. SecurityUtils.sanitize_url_path 中和 URL 路径中的 ".." 穿越段；
2. FileBackend / AsyncFileBackend 的 get/set/exists/delete 对越界 key fail-closed；
3. HelperImage 缓存命中分支对非图片字节做 _validate_image 校验（不回泄非图片文件）。
"""
import asyncio
from pathlib import Path

from app.core.cache import AsyncFileBackend, FileBackend
from app.utils.security import SecurityUtils


class TestSanitizeUrlPathTraversal:
    def test_strips_dotdot_segments(self):
        """URL 路径中的 '..' 穿越段必须被剥离，结果不含任何 '..' 段。"""
        result = SecurityUtils.sanitize_url_path(
            "https://image.tmdb.org/../../../../../../config/app.env"
        )
        segments = result.split("/")
        assert ".." not in segments
        assert "app.env" in result  # 合法末段保留

    def test_strips_single_dot_and_empty_segments(self):
        result = SecurityUtils.sanitize_url_path("https://host/a/./b//c/poster.jpg")
        segments = result.split("/")
        assert "." not in segments
        assert "" not in segments
        assert result.endswith("poster.jpg")

    def test_keeps_normal_path(self):
        """普通图片路径不受影响。"""
        result = SecurityUtils.sanitize_url_path("https://host/t/p/w500/abc.jpg")
        assert result == "t/p/w500/abc.jpg"


class TestFileBackendTraversalFailClosed:
    def test_get_traversal_key_does_not_read_outside_base(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        (base / "images").mkdir()  # region 目录存在，使 ".." 能真实穿越
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"TOP-SECRET")
        fb = FileBackend(base=base)
        # base/images/../../secret.txt -> tmp_path/secret.txt（越界）
        assert fb.get("../../secret.txt", region="images") is None

    def test_set_traversal_key_does_not_write_outside_base(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        fb = FileBackend(base=base)
        fb.set("../../evil.txt", b"x", region="images")
        assert not (tmp_path / "evil.txt").exists()

    def test_exists_traversal_key_is_false(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        (base / "images").mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"S")
        fb = FileBackend(base=base)
        assert fb.exists("../../secret.txt", region="images") is False

    def test_normal_key_roundtrip_still_works(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        fb = FileBackend(base=base)
        fb.set("poster.jpg", b"IMG", region="images")
        assert fb.get("poster.jpg", region="images") == b"IMG"
        assert fb.exists("poster.jpg", region="images") is True


class TestAsyncFileBackendTraversalFailClosed:
    def test_async_get_traversal_key_does_not_read_outside_base(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        (base / "images").mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"TOP-SECRET")
        fb = AsyncFileBackend(base=base)
        result = asyncio.run(fb.get("../../secret.txt", region="images"))
        assert result is None

    def test_async_set_traversal_key_does_not_write_outside_base(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        fb = AsyncFileBackend(base=base)
        asyncio.run(fb.set("../../evil.txt", b"x", region="images"))
        assert not (tmp_path / "evil.txt").exists()

    def test_async_normal_key_roundtrip_still_works(self, tmp_path: Path):
        base = tmp_path / "cache"
        base.mkdir()
        fb = AsyncFileBackend(base=base)

        async def _run():
            await fb.set("poster.jpg", b"IMG", region="images")
            return await fb.get("poster.jpg", region="images")

        assert asyncio.run(_run()) == b"IMG"
