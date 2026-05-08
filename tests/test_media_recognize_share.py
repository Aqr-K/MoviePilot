import asyncio
import sys
import unittest
from types import ModuleType
from unittest.mock import AsyncMock, patch

sys.modules.setdefault("qbittorrentapi", ModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", ModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)
sys.modules.setdefault("psutil", ModuleType("psutil"))

from app.chain import ChainBase
from app.core.context import MediaInfo
from app.core.meta import MetaBase
from app.helper.recognize import MediaRecognizeShareHelper
from app.schemas.types import MediaType


class TestMediaRecognizeShare(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = ChainBase()

    @staticmethod
    def _build_meta(name: str, media_type: MediaType = MediaType.UNKNOWN) -> MetaBase:
        """
        构造测试用元数据
        """
        meta = MetaBase(name)
        meta.name = name
        meta.type = media_type
        return meta

    def test_report_shared_result_after_local_recognize_success(self):
        """
        本地识别成功后应上报共享识别结果
        """
        meta = self._build_meta("测试电影", MediaType.MOVIE)
        mediainfo = MediaInfo(title="测试电影", year="2024", tmdb_id=100, type=MediaType.MOVIE)

        with patch.object(self.chain, "run_module", return_value=mediainfo) as run_module, patch(
            "app.chain.MediaRecognizeShareHelper.report",
            return_value=True,
        ) as report_mock, patch(
            "app.chain.MediaRecognizeShareHelper.query"
        ) as query_mock:
            result = self.chain.recognize_media(meta=meta, cache=False)

        self.assertIs(result, mediainfo)
        run_module.assert_called_once()
        report_mock.assert_called_once_with(meta=meta, mediainfo=mediainfo)
        query_mock.assert_not_called()

    def test_query_shared_result_when_local_recognize_failed(self):
        """
        本地识别失败后应回查共享识别结果，并按共享ID再次识别
        """
        meta = self._build_meta("测试剧集")
        shared_media = MediaInfo(title="测试剧集", year="2024", tmdb_id=200, type=MediaType.TV)

        with patch.object(
            self.chain,
            "run_module",
            side_effect=[None, shared_media],
        ) as run_module, patch(
            "app.chain.MediaRecognizeShareHelper.query",
            return_value={"type": "tv", "tmdbid": 200, "season": 1},
        ) as query_mock, patch(
            "app.chain.MediaRecognizeShareHelper.to_recognize_params",
            return_value={
                "mtype": MediaType.TV,
                "tmdbid": 200,
                "doubanid": None,
                "bangumiid": None,
                "season": 1,
            },
        ), patch(
            "app.chain.MediaRecognizeShareHelper.report",
            return_value=False,
        ), patch.object(
            self.chain,
            "_update_local_recognize_cache",
        ):
            result = self.chain.recognize_media(meta=meta, cache=False)

        self.assertIs(result, shared_media)
        self.assertEqual(run_module.call_count, 2)
        query_mock.assert_called_once_with(meta=meta, mtype=None)
        second_call = run_module.call_args_list[1]
        self.assertEqual(second_call.kwargs["tmdbid"], 200)
        self.assertEqual(second_call.kwargs["mtype"], MediaType.TV)
        self.assertIsNone(meta.begin_season)

    def test_async_query_shared_result_when_local_recognize_failed(self):
        """
        异步识别失败后也应回查共享识别结果
        """
        meta = self._build_meta("测试异步剧集")
        shared_media = MediaInfo(title="测试异步剧集", year="2025", tmdb_id=300, type=MediaType.TV)
        async_run_module = AsyncMock(side_effect=[None, shared_media])

        async def runner():
            with patch.object(
                self.chain,
                "async_run_module",
                async_run_module,
            ), patch(
                "app.chain.MediaRecognizeShareHelper.async_query",
                AsyncMock(return_value={"type": "tv", "tmdbid": 300, "season": 2}),
            ) as query_mock, patch(
                "app.chain.MediaRecognizeShareHelper.to_recognize_params",
                return_value={
                    "mtype": MediaType.TV,
                    "tmdbid": 300,
                    "doubanid": None,
                    "bangumiid": None,
                    "season": 2,
                },
            ), patch(
                "app.chain.MediaRecognizeShareHelper.async_report",
                AsyncMock(return_value=False),
            ), patch.object(
                self.chain,
                "_async_update_local_recognize_cache",
                AsyncMock(),
            ) as backfill_mock:
                result = await self.chain.async_recognize_media(meta=meta, cache=False)
            return result, query_mock, backfill_mock

        result, query_mock, backfill_mock = asyncio.run(runner())

        self.assertIs(result, shared_media)
        self.assertEqual(async_run_module.await_count, 2)
        query_mock.assert_awaited_once_with(meta=meta, mtype=None)
        backfill_mock.assert_awaited_once()
        self.assertIsNone(meta.begin_season)

    def test_backfill_local_cache_after_shared_recognize_success(self):
        """
        共享识别后二次本地识别成功时，应回填原始名称对应的本地识别缓存。
        """
        meta = self._build_meta("测试缓存回填", MediaType.MOVIE)
        shared_media = MediaInfo(
            title="测试缓存回填",
            year="2024",
            tmdb_id=700,
            type=MediaType.MOVIE,
            source="themoviedb",
            tmdb_info={"id": 700, "media_type": MediaType.MOVIE, "title": "测试缓存回填"},
        )

        with patch.object(
            self.chain,
            "run_module",
            side_effect=[None, shared_media],
        ), patch(
            "app.chain.MediaRecognizeShareHelper.query",
            return_value={"type": "movie", "tmdbid": 700},
        ), patch(
            "app.chain.MediaRecognizeShareHelper.to_recognize_params",
            return_value={
                "mtype": MediaType.MOVIE,
                "tmdbid": 700,
                "doubanid": None,
                "bangumiid": None,
                "season": None,
            },
        ), patch(
            "app.chain.MediaRecognizeShareHelper.report",
            return_value=False,
        ), patch.object(
            self.chain,
            "_update_local_recognize_cache",
        ) as backfill_mock:
            result = self.chain.recognize_media(meta=meta, cache=False)

        self.assertIs(result, shared_media)
        backfill_mock.assert_called_once()
        backfill_meta, backfill_media = backfill_mock.call_args.args
        self.assertIsNot(backfill_meta, meta)
        self.assertEqual(backfill_meta.name, meta.name)
        self.assertEqual(backfill_meta.type, meta.type)
        self.assertIs(backfill_media, shared_media)

    def test_query_and_report_prefer_original_name_keyword(self):
        """
        查询和上报共享识别时应优先使用未应用识别词的识别名称
        """
        helper = MediaRecognizeShareHelper()
        meta = self._build_meta("应用识别词后的名称", MediaType.TV)
        meta.original_name = "未应用识别词的名称"
        meta.year = "2024"
        meta.begin_season = 1
        mediainfo = MediaInfo(
            title="测试剧集",
            year="2024",
            tmdb_id=400,
            type=MediaType.TV,
            season=1,
        )

        query_params = helper._build_query_params(meta=meta)
        report_payload = helper._build_report_payload(meta=meta, mediainfo=mediainfo)

        self.assertEqual(query_params["keyword"], "未应用识别词的名称")
        self.assertEqual(report_payload["keyword"], "未应用识别词的名称")

    def test_skip_report_when_local_recognize_hits_cache(self):
        """
        本地识别命中缓存时不应上报共享识别
        """
        meta = self._build_meta("缓存电影", MediaType.MOVIE)
        mediainfo = MediaInfo(title="缓存电影", year="2024", tmdb_id=500, type=MediaType.MOVIE)
        mediainfo.recognize_cache_hit = True

        with patch.object(self.chain, "run_module", return_value=mediainfo) as run_module, patch(
            "app.chain.MediaRecognizeShareHelper.report",
            return_value=True,
        ) as report_mock, patch(
            "app.chain.MediaRecognizeShareHelper.query"
        ) as query_mock:
            result = self.chain.recognize_media(meta=meta)

        self.assertIs(result, mediainfo)
        run_module.assert_called_once()
        report_mock.assert_not_called()
        query_mock.assert_not_called()

    def test_async_skip_report_when_local_recognize_hits_cache(self):
        """
        异步本地识别命中缓存时不应上报共享识别
        """
        meta = self._build_meta("缓存剧集", MediaType.TV)
        mediainfo = MediaInfo(title="缓存剧集", year="2025", tmdb_id=600, type=MediaType.TV)
        mediainfo.recognize_cache_hit = True

        async def runner():
            with patch.object(
                self.chain,
                "async_run_module",
                AsyncMock(return_value=mediainfo),
            ) as async_run_module, patch(
                "app.chain.MediaRecognizeShareHelper.async_report",
                AsyncMock(return_value=True),
            ) as report_mock, patch(
                "app.chain.MediaRecognizeShareHelper.async_query",
                AsyncMock(),
            ) as query_mock:
                result = await self.chain.async_recognize_media(meta=meta)
            return result, async_run_module, report_mock, query_mock

        result, async_run_module, report_mock, query_mock = asyncio.run(runner())

        self.assertIs(result, mediainfo)
        async_run_module.assert_awaited_once()
        report_mock.assert_not_awaited()
        query_mock.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
