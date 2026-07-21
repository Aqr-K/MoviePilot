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

工厂函数（make_transfer_chain/make_task/make_media_info）来自共享模块
tests/transfer_fixtures.py（tests 为包，`from tests.transfer_fixtures import ...`）。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.transfer_fixtures import make_media_info, make_task, make_transfer_chain


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


class TransferHandleRecognitionPathTest(unittest.TestCase):
    """覆盖 block-1（识别块）的两条此前未覆盖路径，作为后续安全抽取 block-1 的安全网。

    （识别失败的完整 add_fail/notify/downloader-hash-completed 路径已由
    test_transfer_job_manager.py:583/612 覆盖。）
    """

    def test_unrecognized_then_recognized_via_history_continues_to_transfer(self):
        """识别成功（经 download_history.tmdbid）：设置 username、回写 mediainfo、
        mediainfo_changed=True 经 _migrate_or_skip 落到 task，流程续走至 self.transfer。"""
        chain = make_transfer_chain()
        task = make_task(1)  # 不预置 mediainfo → 进入 block-1 识别分支
        task.downloader = "qbittorrent"
        task.download_hash = "h1"
        task.download_history = SimpleNamespace(
            username="alice",
            tmdbid=12345,
            doubanid=None,
            bangumiid=None,
            anilistid=None,
            media_source="themoviedb",
            media_id="12345",
            type="电视剧",
            episode_group=None,
            media_category=None,
        )
        # 预置非空 episodes_info → 识别后 _resolve_episodes_info 跳过 TMDB 集数查询
        task.episodes_info = [SimpleNamespace(episode_number=1)]
        self.assertTrue(chain.jobview.add_task(task))

        recognized = make_media_info()
        chain.recognize_media = lambda **kw: recognized
        chain.obtain_images = lambda **kw: None
        transferinfo = SimpleNamespace(success=True, message="整理完成")
        chain.transfer = lambda **kw: transferinfo

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=SimpleNamespace(
                add_fail=lambda **kw: SimpleNamespace(id=1),
                get_by_type_tmdbid=lambda **kw: None,
            ),
        ), patch(
            "app.chain.transfer.DirectoryHelper",
            return_value=SimpleNamespace(
                get_dir=lambda **kw: SimpleNamespace(library_storage="local")
            ),
        ), patch(
            "app.chain.transfer.eventmanager.send_event", return_value=None
        ):
            result = chain._TransferChain__handle_transfer(task)

        self.assertEqual((True, "整理完成"), result)
        # 识别结果经 _migrate_or_skip 回写到 task（多值回流契约）
        self.assertIs(recognized, task.mediainfo)
        # block-1 从 download_history 取下载用户
        self.assertEqual("alice", task.username)

    def test_unrecognized_preview_short_circuits_without_side_effects(self):
        """preview 模式识别失败：在 add_fail/post_message 之前短路返回，二者均不触发。"""
        chain = make_transfer_chain()
        task = make_task(1)
        task.preview = True
        task.download_history = None  # → 走 MediaChain().recognize_by_meta 分支
        add_fail_called = []
        post_called = []
        chain.post_message = lambda *a, **k: post_called.append(1)
        self.assertTrue(chain.jobview.add_task(task))

        with patch(
            "app.chain.transfer.TransferHistoryOper",
            return_value=SimpleNamespace(
                add_fail=lambda **kw: (add_fail_called.append(1) or SimpleNamespace(id=1)),
                get_by_type_tmdbid=lambda **kw: None,
            ),
        ), patch("app.chain.transfer.MediaChain") as media_chain_cls:
            media_chain_cls.return_value.recognize_by_meta.return_value = None
            result = chain._TransferChain__handle_transfer(task)

        self.assertEqual((False, "未识别到媒体信息"), result)
        # preview 短路必须发生在副作用之前
        self.assertEqual([], add_fail_called)
        self.assertEqual([], post_called)


if __name__ == "__main__":
    unittest.main()
