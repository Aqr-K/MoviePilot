"""transfer 测试共享工厂（单一来源）。

此前 make_transfer_chain/make_task/make_media_info/FakeMeta/FakeMedia/make_fileitem/
migrate_to_media_job 在 test_transfer_job_manager.py 与 test_transfer_handle_integration.py
两处重复，现集中于此（``from tests.transfer_fixtures import ...``，tests 为包）。

S8-step2：新增 make_queue_chain()——在 make_transfer_chain 基础上额外种入队列/守护/计数器
机器属性（不起线程），使 worker loop (__start_transfer) 可在 venv 内被受控驱动，作为后续
抽取 TransferService 前的特征化测试安全网的基础。
"""
from unittest.mock import Mock

from app.core.config import settings
from app.core.context import MediaInfo
from app.chain.transfer import (
    JobManager,
    ScrapeBatchCoordinator,
    TransferChain,
    TransferResultProcessor,
    TransferService,
)
from app.schemas import FileItem, TransferTask
from app.schemas.types import MediaType


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
        """构造与正式 MediaInfo 身份字段一致的测试媒体对象。"""
        self.tmdb_id = tmdb_id
        self.douban_id = None
        self.bangumi_id = None
        self.anilist_id = None
        self.source = "themoviedb"
        self.type = MediaType.TV
        self.title_year = "Test Show (2026)"

    def clear(self):
        """模拟正式媒体对象的清理接口。"""
        pass

    def to_dict(self):
        """返回测试媒体对象的序列化字段。"""
        return {
            "type": MediaType.TV.value,
            "title": "Test Show",
            "year": "2026",
            "title_year": "Test Show (2026)",
            "tmdb_id": self.tmdb_id,
            "douban_id": self.douban_id,
            "bangumi_id": self.bangumi_id,
            "anilist_id": self.anilist_id,
        }


def make_media_info() -> MediaInfo:
    media = MediaInfo()
    media.type = MediaType.TV
    media.title = "Test Show"
    media.title_year = "Test Show (2026)"
    media.year = "2026"
    media.tmdb_id = 12345
    media.category = ""
    media.actors = []
    media.season_years = {}
    media.vote_average = 0
    return media


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
    chain._scrape_coordinator = ScrapeBatchCoordinator(chain=chain)
    chain._result_processor = TransferResultProcessor(chain=chain)
    return chain


def make_fileitem(path: str, size: int = 1024) -> FileItem:
    file_path = path
    name = file_path.rsplit("/", 1)[-1]
    suffix = name.rsplit(".", 1)[-1] if "." in name else ""
    basename = name[: -(len(suffix) + 1)] if suffix else name
    return FileItem(
        storage="local",
        path=file_path,
        type="file",
        name=name,
        basename=basename,
        extension=suffix,
        size=size,
    )


def migrate_to_media_job(jobview: JobManager, task: TransferTask):
    task.mediainfo = FakeMedia()
    jobview.migrate_task(task)
    jobview.running_task(task)
    jobview.finish_task(task)
    jobview.try_remove_job(task)


def make_queue_chain() -> TransferChain:
    """make_transfer_chain + 组合一个未起线程的 TransferService（队列/守护/计数器机器）。

    S8-step2 ⑤：队列机器已从 TransferChain 抽到 TransferService（组合于 ``chain._service``）。
    本工厂构造一个不 spawn 线程的 service（_transfer_interval 取极小、_progress 用 Mock），
    使 worker loop (run_worker) / 生命周期 (start/stop) 在 venv 内可被受控驱动，而无需真实
    daemon 线程（真实 TransferChain() 会经 service.start() 起线程并阻塞在 _queue.get(15s)）。

    注意：返回的 service 处于「已构造未 start」态（``_queue_active=False``、``_threads=[]``）。
    直接驱动 worker 前须先翻 ``svc._queue_active = True``（``_drain_worker`` 已代为处理），
    否则 ``run_worker`` 的 ``while ... and self._queue_active`` 会在首轮即退出。
    """
    chain = make_transfer_chain()
    service = TransferService(chain=chain)
    service._transfer_interval = 0.01
    service._progress = Mock()
    chain._service = service
    return chain
