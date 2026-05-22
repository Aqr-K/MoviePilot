import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from watchfiles import Change

from app.monitor import DirectoryChangeEvent, LocalDirectoryWatcher, Monitor


class CallbackRecorder:
    """
    测试用目录监控回调记录器。
    """

    def __init__(self):
        """
        初始化事件记录列表。
        """
        self.events = []

    def event_handler(self, event, text: str, event_path: str, file_size: int = None):
        """
        记录目录监控分发出来的事件。
        :param event: 目录监控事件
        :param text: 事件描述
        :param event_path: 事件路径
        :param file_size: 文件大小
        """
        self.events.append((event, text, event_path, file_size))


class LocalDirectoryWatcherTest(unittest.TestCase):
    """
    watchfiles 本地目录监控测试。
    """

    def test_handle_changes_dispatches_added_and_modified_files(self):
        """
        新增和修改文件应转换成目录监控整理回调。
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            watch_dir = Path(temp_dir)
            added_file = watch_dir / "a_added.mkv"
            modified_file = watch_dir / "b_modified.mkv"
            skipped_dir = watch_dir / "c_dir"
            added_file.write_bytes(b"added")
            modified_file.write_bytes(b"modified")
            skipped_dir.mkdir()

            callback = CallbackRecorder()
            watcher = LocalDirectoryWatcher(watch_dir, callback=callback, force_polling=True)
            watcher._handle_changes({
                (Change.added, added_file.as_posix()),
                (Change.modified, modified_file.as_posix()),
                (Change.deleted, added_file.as_posix()),
                (Change.added, skipped_dir.as_posix()),
            })

            self.assertEqual(2, len(callback.events))
            self.assertEqual((Change.added, "新增", added_file.as_posix(), 5),
                             (callback.events[0][0].change_type,
                              callback.events[0][1],
                              callback.events[0][2],
                              callback.events[0][3]))
            self.assertEqual((Change.modified, "修改", modified_file.as_posix(), 8),
                             (callback.events[1][0].change_type,
                              callback.events[1][1],
                              callback.events[1][2],
                              callback.events[1][3]))

    def test_handle_changes_skips_missing_paths(self):
        """
        事件到达时已经消失的路径不应触发整理。
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            watch_dir = Path(temp_dir)
            missing_file = watch_dir / "missing.mkv"

            callback = CallbackRecorder()
            watcher = LocalDirectoryWatcher(watch_dir, callback=callback, force_polling=True)
            watcher._handle_changes({(Change.added, missing_file.as_posix())})

            self.assertEqual([], callback.events)


class MonitorWatchfilesEventTest(unittest.TestCase):
    """
    Monitor 对 watchfiles 事件的兼容处理测试。
    """

    def test_event_handler_routes_file_events_to_transfer_handler(self):
        """
        文件事件应继续按 local 存储交给整理流程。
        """
        monitor = object.__new__(Monitor)
        handle_file = MagicMock()
        setattr(monitor, "_Monitor__handle_file", handle_file)
        event_path = Path("/downloads/movie.mkv")
        event = DirectoryChangeEvent(
            change_type=Change.added,
            src_path=event_path.as_posix(),
            is_directory=False
        )

        monitor.event_handler(
            event=event,
            text="新增",
            event_path=event_path.as_posix(),
            file_size=1024
        )

        handle_file.assert_called_once_with(
            storage="local",
            event_path=event_path,
            file_size=1024
        )

    def test_event_handler_ignores_directory_events(self):
        """
        目录事件不应进入文件整理流程。
        """
        monitor = object.__new__(Monitor)
        handle_file = MagicMock()
        setattr(monitor, "_Monitor__handle_file", handle_file)
        event_path = Path("/downloads/folder")
        event = DirectoryChangeEvent(
            change_type=Change.added,
            src_path=event_path.as_posix(),
            is_directory=True
        )

        monitor.event_handler(
            event=event,
            text="新增",
            event_path=event_path.as_posix()
        )

        handle_file.assert_not_called()
