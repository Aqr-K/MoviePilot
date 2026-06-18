"""
S8b 集成夹具：驱动**真实** __handle_transfer 走「已识别 mediainfo → do_transfer → 返回/回调」
happy path。

目的有二：
1. 补上 transfer 流水线在 venv 内的集成覆盖缺口——现有测试仅驱动识别失败分支
   (test_transfer_job_manager.py:583/612)，成功路径（穿过 _migrate_or_skip/_resolve_*/
   _select_storage_opers 直到 self.transfer 与 callback 委派）此前零集成覆盖。
2. 作为后续安全抽 block-1（识别块，多值回流）/ block-7（transfer+callback）/ step2
   （TransferService）的安全网。

设计：预置 task.mediainfo 跳过识别分支（block-1），预置非空 episodes_info 跳过
_resolve_episodes_info 的 TMDB 集数查询（同时绕开 FakeMeta 无 season_seq 的坑）。
mock 边界（3 patch + 1 实例方法替换）：
  - app.chain.transfer.TransferHistoryOper   （仅构造；_apply_scrap_follow_tmdb 用其只读查询）
  - app.chain.transfer.DirectoryHelper.get_dir（目标目录解析，返回带 library_storage 的假目录）
  - app.chain.transfer.eventmanager.send_event（_select_storage_opers 广播存储选择事件，返回 None）
  - chain.transfer                            （替换 run_module('transfer') 真实文件搬运）
真实运行：JobManager（内存）、_apply_scrap_follow_tmdb/_migrate_or_skip/_resolve_target_directory/
_select_storage_opers 编排、try/finally 清理（try_remove_job + __finish_scrape_batch_task 空态返回）。

工厂函数（make_transfer_chain/make_task/make_media_info/FakeMeta）就地内联自
test_transfer_job_manager 的同名实现——本仓库 pytest 导入模式不把 tests/ 暴露为顶层包，
同级测试模块不可直接 import，故复制必要工厂（测试夹具，受控重复）。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.core.config import settings
from app.core.context import MediaInfo
from app.chain.transfer import JobManager, TransferChain
from app.schemas import FileItem, TransferTask
from app.schemas.types import MediaType


class FakeMeta:
    """TV 元数据（复制自 test_transfer_job_manager.FakeMeta，含 add_task 所需的 to_dict）。"""

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
        meta=FakeMeta(episode, season),
    )


def make_transfer_chain() -> TransferChain:
    chain = object.__new__(TransferChain)
    chain.jobview = JobManager()
    chain._media_exts = settings.RMT_MEDIAEXT
    chain._subtitle_exts = settings.RMT_SUBEXT
    chain._audio_exts = settings.RMT_AUDIOEXT
    chain._allowed_exts = chain._media_exts + chain._audio_exts + chain._subtitle_exts
    chain._success_target_files = {}
    chain._scrape_batches = {}
    return chain


def _prepare_recognized_task():
    """构造一个已识别的整理任务：预置 mediainfo + episodes_info，跳过识别与 TMDB 集数查询。"""
    task = make_task(1)
    task.mediainfo = make_media_info()
    # 预置非空 episodes_info → _resolve_episodes_info 整块跳过（不触 TmdbChain、不读 FakeMeta.season_seq）
    task.episodes_info = [SimpleNamespace(episode_number=1)]
    task.downloader = "qbittorrent"
    task.download_hash = "hash-itest"
    return task


def _apply_patches(chain, transferinfo):
    """统一的 mock 边界：替换 chain.transfer 并返回 3 个 patch 上下文管理器。"""
    chain.transfer = lambda **kw: transferinfo
    transfer_history_oper = SimpleNamespace(
        add_fail=lambda **kw: SimpleNamespace(id=1),
        get_by_type_tmdbid=lambda **kw: None,
    )
    fake_dir = SimpleNamespace(library_storage="local")
    return (
        patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=transfer_history_oper,
        ),
        patch(
            "app.chain.transfer.DirectoryHelper",
            return_value=SimpleNamespace(get_dir=lambda **kw: fake_dir),
        ),
        patch("app.chain.transfer.eventmanager.send_event", return_value=None),
    )


class TransferHandleHappyPathTest(unittest.TestCase):
    def test_recognized_media_no_callback_returns_transferinfo_tuple(self):
        """已识别 + 无 callback：流程直达 self.transfer，返回 (success, message)，finally 清理作业视图。"""
        chain = make_transfer_chain()
        task = _prepare_recognized_task()
        self.assertTrue(chain.jobview.add_task(task))
        transferinfo = SimpleNamespace(success=True, message="整理完成")

        p1, p2, p3 = _apply_patches(chain, transferinfo)
        with p1, p2, p3:
            result = chain._TransferChain__handle_transfer(task)

        self.assertEqual((True, "整理完成"), result)
        # 目标存储由 _resolve_target_directory 从假目录的 library_storage 派生
        self.assertEqual("local", task.target_storage)
        # _select_storage_opers 已把任务置运行中；成功后的 finish/remove 由 callback 负责，
        # 本无-callback 场景不触发，故 finally(try_remove_job) 不移除运行中任务，作业仍在视图
        jobs = chain.jobview.list_jobs()
        self.assertEqual(1, len(jobs))
        self.assertEqual("running", jobs[0].tasks[0].state)

    def test_recognized_media_with_callback_delegates_tuple(self):
        """已识别 + callback：__handle_transfer 把 (task, transferinfo) 委派给 callback 并返回其结果。"""
        chain = make_transfer_chain()
        task = _prepare_recognized_task()
        self.assertTrue(chain.jobview.add_task(task))
        transferinfo = SimpleNamespace(success=True, message="整理完成")
        seen = []

        def callback(t, info):
            seen.append((t, info))
            return True, "via-callback"

        p1, p2, p3 = _apply_patches(chain, transferinfo)
        with p1, p2, p3:
            result = chain._TransferChain__handle_transfer(task, callback=callback)

        self.assertEqual((True, "via-callback"), result)
        self.assertEqual(1, len(seen))
        self.assertIs(task, seen[0][0])
        self.assertIs(transferinfo, seen[0][1])

    def test_transfer_module_failure_returns_module_error(self):
        """self.transfer 返回 falsy（模块失败）：返回 (False, '文件整理模块运行失败')，finally 仍清理。"""
        chain = make_transfer_chain()
        task = _prepare_recognized_task()
        self.assertTrue(chain.jobview.add_task(task))

        p1, p2, p3 = _apply_patches(chain, None)  # transfer 返回 None
        with p1, p2, p3:
            result = chain._TransferChain__handle_transfer(task)

        self.assertEqual((False, "文件整理模块运行失败"), result)


if __name__ == "__main__":
    unittest.main()
