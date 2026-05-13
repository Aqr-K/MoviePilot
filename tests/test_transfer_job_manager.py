import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from app.core.config import settings
from app.chain.transfer import JobManager, TransferChain
from app.schemas import FileItem, TransferInfo, TransferTask
from app.schemas.types import EventType, MediaType


class FakeMeta:
    def __init__(self, episode: int, season: int = 1):
        self.name = "Test Show"
        self.title = f"Test Show S{season:02d}E{episode:02d}"
        self.year = "2026"
        self.type = MediaType.TV
        self.begin_season = season
        self.end_season = None
        self.total_season = 1
        self.begin_episode = episode
        self.end_episode = None
        self.total_episode = 1
        self.episode_list = [episode]
        self.season_episode = f"S01E{episode:02d}"
        self.part = None

    @property
    def season(self):
        return f"S{self.begin_season:02d}"

    @property
    def episode(self):
        return f"E{self.begin_episode:02d}"

    def to_dict(self):
        return {
            "title": self.title,
            "name": self.name,
            "year": self.year,
            "type": self.type.value,
            "begin_season": self.begin_season,
            "end_season": self.end_season,
            "total_season": self.total_season,
            "begin_episode": self.begin_episode,
            "end_episode": self.end_episode,
            "total_episode": self.total_episode,
            "season_episode": self.season_episode,
            "episode_list": self.episode_list,
            "part": self.part,
        }


class FakeMedia:
    def __init__(self, tmdb_id: int = 12345):
        self.tmdb_id = tmdb_id
        self.douban_id = None
        self.type = MediaType.TV
        self.title_year = "Test Show (2026)"

    def clear(self):
        pass

    def to_dict(self):
        return {
            "type": MediaType.TV.value,
            "title": "Test Show",
            "year": "2026",
            "title_year": "Test Show (2026)",
            "tmdb_id": self.tmdb_id,
            "douban_id": self.douban_id,
        }


def make_task(episode: int, season: int = 1) -> TransferTask:
    name = f"Test.Show.S{season:02d}E{episode:02d}.mkv"
    return TransferTask(
        fileitem=FileItem(
            storage="local",
            path=f"/downloads/Test Show/{name}",
            type="file",
            name=name,
            basename=name.removesuffix(".mkv"),
            extension="mkv",
            size=1024,
        ),
        meta=FakeMeta(episode),
    )


def make_transfer_chain() -> TransferChain:
    chain = object.__new__(TransferChain)
    chain.jobview = JobManager()
    chain._media_exts = settings.RMT_MEDIAEXT
    chain._subtitle_exts = settings.RMT_SUBEXT
    chain._audio_exts = settings.RMT_AUDIOEXT
    chain._allowed_exts = (
        chain._media_exts + chain._audio_exts + chain._subtitle_exts
    )
    chain._success_target_files = {}
    chain._scrape_batches = {}
    return chain


def migrate_to_media_job(jobview: JobManager, task: TransferTask):
    task.mediainfo = FakeMedia()
    jobview.migrate_task(task)
    jobview.running_task(task)
    jobview.finish_task(task)
    jobview.try_remove_job(task)


class TransferJobManagerTest(unittest.TestCase):
    def test_completed_media_job_is_removed_after_last_meta_task_fails(self):
        jobview = JobManager()
        tasks = [make_task(episode) for episode in range(1, 4)]
        for task in tasks:
            self.assertTrue(jobview.add_task(task))

        migrate_to_media_job(jobview, tasks[0])
        migrate_to_media_job(jobview, tasks[1])

        # 还有一个 meta 任务未处理时，media 组虽然已完成也不能提前清理。
        self.assertEqual(2, len(jobview.list_jobs()))

        # 最后一个仍在 meta 组中的任务未识别，__handle_transfer 会直接 remove_task 后 return。
        jobview.remove_task(tasks[2].fileitem)
        jobview.try_remove_job(tasks[2])

        self.assertEqual([], jobview.list_jobs())

    def test_completed_media_job_is_removed_after_all_meta_tasks_migrate(self):
        jobview = JobManager()
        tasks = [make_task(episode) for episode in range(1, 3)]
        for task in tasks:
            self.assertTrue(jobview.add_task(task))

        migrate_to_media_job(jobview, tasks[0])
        self.assertEqual(2, len(jobview.list_jobs()))

        migrate_to_media_job(jobview, tasks[1])
        self.assertEqual([], jobview.list_jobs())

    def test_exception_marks_unfinished_meta_task_failed_and_cleans_jobs(self):
        jobview = JobManager()
        tasks = [make_task(episode) for episode in range(1, 3)]
        for task in tasks:
            self.assertTrue(jobview.add_task(task))

        migrate_to_media_job(jobview, tasks[0])
        jobview.running_task(tasks[1])

        jobview.fail_unfinished_task(tasks[1])
        jobview.try_remove_job(tasks[1])

        self.assertEqual([], jobview.list_jobs())

    def test_exception_marks_unfinished_media_task_failed_and_cleans_jobs(self):
        jobview = JobManager()
        task = make_task(1)
        self.assertTrue(jobview.add_task(task))

        task.mediainfo = FakeMedia()
        jobview.migrate_task(task)
        jobview.running_task(task)

        jobview.fail_unfinished_task(task)
        jobview.try_remove_job(task)

        self.assertEqual([], jobview.list_jobs())

    def test_pre_recognized_jobs_with_same_meta_do_not_block_each_other(self):
        jobview = JobManager()
        task1 = make_task(1)
        task2 = make_task(2)
        task1.mediainfo = FakeMedia(100)
        task2.mediainfo = FakeMedia(200)

        self.assertTrue(jobview.add_task(task1))
        self.assertTrue(jobview.add_task(task2))

        jobview.running_task(task1)
        jobview.finish_task(task1)
        jobview.try_remove_job(task1)

        jobs = jobview.list_jobs()
        self.assertEqual(1, len(jobs))
        self.assertEqual(task2.fileitem, jobs[0].tasks[0].fileitem)

    def test_pre_recognized_migrations_with_same_meta_do_not_link_jobs(self):
        jobview = JobManager()
        task1 = make_task(1)
        task2 = make_task(2)
        task1.mediainfo = FakeMedia(100)
        task2.mediainfo = FakeMedia(200)

        self.assertTrue(jobview.add_task(task1))
        self.assertTrue(jobview.add_task(task2))

        self.assertTrue(jobview.migrate_task(task1))
        self.assertTrue(jobview.migrate_task(task2))
        jobview.running_task(task1)
        jobview.finish_task(task1)
        jobview.try_remove_job(task1)

        jobs = jobview.list_jobs()
        self.assertEqual(1, len(jobs))
        self.assertEqual(task2.fileitem, jobs[0].tasks[0].fileitem)

    def test_exception_failure_does_not_mark_downloader_without_history(self):
        chain = make_transfer_chain()
        completed = []

        def fake_transfer_completed(hashs, downloader):
            completed.append((hashs, downloader))

        chain.transfer_completed = fake_transfer_completed
        task = make_task(1)
        task.downloader = "qbittorrent"
        task.download_hash = "abc123"
        self.assertTrue(chain.jobview.add_task(task))
        chain.jobview.running_task(task)

        chain._TransferChain__fail_transfer_task(task)

        self.assertEqual([], completed)
        self.assertEqual([], chain.jobview.list_jobs())

    def test_successful_history_skip_marks_downloader_hash_completed(self):
        chain = make_transfer_chain()
        completed = []

        def fake_transfer_completed(hashs, downloader):
            completed.append((hashs, downloader))

        chain.transfer_completed = fake_transfer_completed
        chain._TransferChain__get_trans_fileitems = lambda fileitem, predicate: [
            (fileitem, False)
        ]

        fileitem = make_task(1).fileitem
        history = SimpleNamespace(
            status=True,
            download_hash="abc123",
            downloader="qbittorrent",
        )
        transfer_history_oper = SimpleNamespace(
            get_by_src=lambda src, storage=None: history
        )
        system_config_oper = SimpleNamespace(get=lambda key: None)

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=transfer_history_oper,
        ), patch(
            "app.chain.transfer.SystemConfigOper",
            return_value=system_config_oper,
        ):
            state, errmsg = TransferChain.do_transfer(
                chain,
                fileitem=fileitem,
                downloader="qbittorrent",
                download_hash="abc123",
                background=False,
            )

        self.assertTrue(state)
        self.assertEqual("Test.Show.S01E01.mkv 已整理过", errmsg)
        self.assertEqual([("abc123", "qbittorrent")], completed)

    def test_failed_history_skip_still_marks_downloader_hash_completed(self):
        chain = make_transfer_chain()
        completed = []

        def fake_transfer_completed(hashs, downloader):
            completed.append((hashs, downloader))

        chain.transfer_completed = fake_transfer_completed
        chain._TransferChain__get_trans_fileitems = lambda fileitem, predicate: [
            (fileitem, False)
        ]

        fileitem = make_task(1).fileitem
        history = SimpleNamespace(
            status=False,
            download_hash="abc123",
            downloader="qbittorrent",
        )
        transfer_history_oper = SimpleNamespace(
            get_by_src=lambda src, storage=None: history
        )
        system_config_oper = SimpleNamespace(get=lambda key: None)

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=transfer_history_oper,
        ), patch(
            "app.chain.transfer.SystemConfigOper",
            return_value=system_config_oper,
        ):
            state, errmsg = TransferChain.do_transfer(
                chain,
                fileitem=fileitem,
                downloader="qbittorrent",
                download_hash="abc123",
                background=False,
            )

        self.assertFalse(state)
        self.assertEqual("Test.Show.S01E01.mkv 已整理过", errmsg)
        self.assertEqual([("abc123", "qbittorrent")], completed)

    def test_unrecognized_task_marks_downloader_hash_completed(self):
        chain = make_transfer_chain()
        chain.post_message = lambda *_args, **_kwargs: None
        completed = []

        def fake_transfer_completed(hashs, downloader):
            completed.append((hashs, downloader))

        chain.transfer_completed = fake_transfer_completed
        task = make_task(1)
        task.downloader = "qbittorrent"
        task.download_hash = "abc123"
        self.assertTrue(chain.jobview.add_task(task))

        transfer_history_oper = SimpleNamespace(
            add_fail=lambda **kwargs: SimpleNamespace(id=1)
        )

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=transfer_history_oper,
        ), patch(
            "app.chain.transfer.MediaChain"
        ) as media_chain_cls, patch(
            "app.chain.transfer.settings.AI_AGENT_ENABLE", False
        ), patch(
            "app.chain.transfer.settings.AI_AGENT_RETRY_TRANSFER", False
        ):
            media_chain_cls.return_value.recognize_by_meta.return_value = None
            state, errmsg = chain._TransferChain__handle_transfer(task)

        self.assertFalse(state)
        self.assertEqual("未识别到媒体信息", errmsg)
        self.assertEqual([("abc123", "qbittorrent")], completed)
        self.assertEqual([], chain.jobview.list_jobs())

    def test_scrape_event_is_aggregated_by_transfer_batch_across_seasons(self):
        chain = make_transfer_chain()
        chain.eventmanager = MagicMock()
        chain.transfer_completed = lambda *args, **kwargs: None

        tasks = [make_task(1, season=1), make_task(1, season=2)]
        target_diritem = FileItem(
            storage="local",
            path="/library/Test Show (2026)",
            type="dir",
            name="Test Show (2026)",
        )
        batch_id = "batch-tv-multi-season"

        for task in tasks:
            task.mediainfo = FakeMedia()
            task.transfer_batch_id = batch_id
            task.background = False
            task.manual = True
            self.assertTrue(chain._TransferChain__put_to_jobview(task))
            chain._TransferChain__register_scrape_batch_task(task)

        chain._TransferChain__close_scrape_batch(batch_id)

        transferinfos = [
            TransferInfo(
                success=True,
                fileitem=tasks[0].fileitem,
                target_diritem=target_diritem,
                target_item=FileItem(
                    storage="local",
                    path="/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv",
                    type="file",
                    name="Test.Show.S01E01.mkv",
                    extension="mkv",
                ),
                file_list_new=[
                    "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"
                ],
                transfer_type="copy",
                need_scrape=True,
                need_notify=False,
            ),
            TransferInfo(
                success=True,
                fileitem=tasks[1].fileitem,
                target_diritem=target_diritem,
                target_item=FileItem(
                    storage="local",
                    path="/library/Test Show (2026)/Season 2/Test.Show.S02E01.mkv",
                    type="file",
                    name="Test.Show.S02E01.mkv",
                    extension="mkv",
                ),
                file_list_new=[
                    "/library/Test Show (2026)/Season 2/Test.Show.S02E01.mkv"
                ],
                transfer_type="copy",
                need_scrape=True,
                need_notify=False,
            ),
        ]

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=SimpleNamespace(add_success=lambda **kwargs: SimpleNamespace(id=1)),
        ), patch(
            "app.chain.transfer.StorageChain"
        ) as storage_chain_cls:
            storage_chain_cls.return_value.is_bluray_folder.return_value = False
            for task, transferinfo in zip(tasks, transferinfos):
                chain._TransferChain__default_callback(task, transferinfo)
                chain._TransferChain__finish_scrape_batch_task(task)

        metadata_calls = [
            call
            for call in chain.eventmanager.send_event.call_args_list
            if call.args[0] == EventType.MetadataScrape
        ]
        self.assertEqual(1, len(metadata_calls))
        event_data = metadata_calls[0].args[1]
        self.assertEqual(target_diritem, event_data["fileitem"])
        self.assertEqual(
            [
                "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv",
                "/library/Test Show (2026)/Season 2/Test.Show.S02E01.mkv",
            ],
            event_data["file_list"],
        )
        self.assertEqual({}, chain._scrape_batches)

    def test_scrape_event_keeps_immediate_behavior_without_transfer_batch(self):
        chain = make_transfer_chain()
        chain.eventmanager = MagicMock()
        chain.transfer_completed = lambda *args, **kwargs: None

        task = make_task(1)
        task.mediainfo = FakeMedia()
        task.background = False
        task.manual = True
        self.assertTrue(chain._TransferChain__put_to_jobview(task))

        target_diritem = FileItem(
            storage="local",
            path="/library/Test Show (2026)",
            type="dir",
            name="Test Show (2026)",
        )
        transferinfo = TransferInfo(
            success=True,
            fileitem=task.fileitem,
            target_diritem=target_diritem,
            target_item=FileItem(
                storage="local",
                path="/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv",
                type="file",
                name="Test.Show.S01E01.mkv",
                extension="mkv",
            ),
            file_list_new=[
                "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"
            ],
            transfer_type="copy",
            need_scrape=True,
            need_notify=False,
        )

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=SimpleNamespace(add_success=lambda **kwargs: SimpleNamespace(id=1)),
        ), patch(
            "app.chain.transfer.StorageChain"
        ) as storage_chain_cls:
            storage_chain_cls.return_value.is_bluray_folder.return_value = False
            chain._TransferChain__default_callback(task, transferinfo)

        metadata_calls = [
            call
            for call in chain.eventmanager.send_event.call_args_list
            if call.args[0] == EventType.MetadataScrape
        ]
        self.assertEqual(1, len(metadata_calls))
        event_data = metadata_calls[0].args[1]
        self.assertEqual(target_diritem, event_data["fileitem"])
        self.assertEqual(
            ["/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"],
            event_data["file_list"],
        )


if __name__ == "__main__":
    unittest.main()
