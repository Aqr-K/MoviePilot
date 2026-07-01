"""#13 回归：RECOGNIZE_SOURCE 非 themoviedb 时 obtain_images 不应发起 TMDB 抓图。

_validate_obtain_images_params 的调用方约定（obtain_images: `if result is not None: return result`）：
返回 MediaInfo → 提前返回（跳过 TMDB 抓图），返回 None → 继续调用 TMDB。
识别源非 TMDB 时必须返回 MediaInfo（跳过），否则会以可能为 None 的 tmdb_id 发起无效 TMDB 请求。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.core.config import settings
from app.modules.themoviedb import TheMovieDbModule


class TestObtainImagesGuard(unittest.TestCase):
    @staticmethod
    def _mediainfo(tmdb_id=None, complete=False):
        p = "x.jpg" if complete else None
        return SimpleNamespace(
            tmdb_id=tmdb_id, logo_path=p, poster_path=p, backdrop_path=p
        )

    def test_non_themoviedb_source_returns_mediainfo_to_skip(self):
        """识别源非 TMDB → 返回 MediaInfo（非 None），调用方提前返回、跳过 TMDB。"""
        mediainfo = self._mediainfo(tmdb_id=None)
        with patch.object(settings, "RECOGNIZE_SOURCE", "douban"):
            result = TheMovieDbModule._validate_obtain_images_params(mediainfo)
        self.assertIs(result, mediainfo)

    def test_themoviedb_source_incomplete_images_returns_none_to_proceed(self):
        """识别源为 TMDB、有 tmdb_id、图不全 → 返回 None，调用方继续抓图。"""
        mediainfo = self._mediainfo(tmdb_id=123, complete=False)
        with patch.object(settings, "RECOGNIZE_SOURCE", "themoviedb"):
            result = TheMovieDbModule._validate_obtain_images_params(mediainfo)
        self.assertIsNone(result)

    def test_themoviedb_source_no_tmdbid_returns_mediainfo_to_skip(self):
        """识别源为 TMDB 但无 tmdb_id → 返回 MediaInfo（跳过），不以 None id 请求 TMDB。"""
        mediainfo = self._mediainfo(tmdb_id=None)
        with patch.object(settings, "RECOGNIZE_SOURCE", "themoviedb"):
            result = TheMovieDbModule._validate_obtain_images_params(mediainfo)
        self.assertIs(result, mediainfo)


if __name__ == "__main__":
    unittest.main()
