# -*- coding: utf-8 -*-
"""
S2 解耦回归测试：下载器 torrent_files() 归一化为 schemas.DownloaderFile,
不再向契约层(ChainBase)泄漏 qbittorrentapi / transmission_rpc 的 SDK 文件类型。

验证：
  1. DownloaderFile schema 基本构造/默认值;
  2. qBittorrent 模块 torrent_files() 把 SDK 文件对象转为 DownloaderFile（含字段映射）;
  3. Transmission 模块 torrent_files() 同上（progress 由 completed/size 计算,index 取 id）;
  4. 契约层不再泄漏:app/chain/__init__.py 不再 import 下载器 SDK,返回类型为 DownloaderFile;
     两个下载器模块不再 import SDK 文件类型。
"""
from pathlib import Path
from unittest import TestCase

from app import schemas
from app.modules.qbittorrent import QbittorrentModule
from app.modules.transmission import TransmissionModule


class _FakeQbFile:
    """模拟 qbittorrentapi 的 TorrentFile（属性可访问）"""
    def __init__(self, name, size, progress, priority, index):
        self.name = name
        self.size = size
        self.progress = progress
        self.priority = priority
        self.index = index


class _FakeTrFile:
    """模拟 transmission_rpc 的 File（completed/size + id）"""
    def __init__(self, name, size, completed, priority, id):
        self.name = name
        self.size = size
        self.completed = completed
        self.priority = priority
        self.id = id


class _FakeServer:
    def __init__(self, files):
        self._files = files

    def get_files(self, tid):
        return self._files


class DownloaderFileNormalizationTest(TestCase):

    def test_schema_defaults(self):
        f = schemas.DownloaderFile()
        self.assertIsNone(f.name)
        self.assertIsNone(f.size)
        self.assertEqual(f.progress, 0.0)
        f2 = schemas.DownloaderFile(name="a/b.mkv", size=100, progress=0.5, priority=1, index=2)
        self.assertEqual(f2.name, "a/b.mkv")
        self.assertEqual(f2.size, 100)

    def test_qbittorrent_torrent_files_normalized(self):
        mod = QbittorrentModule.__new__(QbittorrentModule)  # 绕过 __init__,避免连接下载器
        mod.get_instance = lambda downloader=None: _FakeServer([_FakeQbFile("a/b.mkv", 100, 0.5, 1, 0)])
        files = QbittorrentModule.torrent_files(mod, tid="hash")
        self.assertIsInstance(files, list)
        self.assertIsInstance(files[0], schemas.DownloaderFile)
        self.assertEqual(files[0].name, "a/b.mkv")
        self.assertEqual(files[0].size, 100)
        self.assertEqual(files[0].progress, 0.5)
        self.assertEqual(files[0].priority, 1)
        self.assertEqual(files[0].index, 0)

    def test_qbittorrent_torrent_files_none_when_no_server(self):
        mod = QbittorrentModule.__new__(QbittorrentModule)
        mod.get_instance = lambda downloader=None: None
        self.assertIsNone(QbittorrentModule.torrent_files(mod, tid="hash"))

    def test_transmission_torrent_files_normalized(self):
        mod = TransmissionModule.__new__(TransmissionModule)
        mod.get_instance = lambda downloader=None: _FakeServer([_FakeTrFile("x.mkv", 200, 100, 1, 3)])
        files = TransmissionModule.torrent_files(mod, tid="hash")
        self.assertIsInstance(files, list)
        self.assertIsInstance(files[0], schemas.DownloaderFile)
        self.assertEqual(files[0].name, "x.mkv")
        self.assertEqual(files[0].size, 200)
        self.assertEqual(files[0].progress, 0.5)  # completed/size = 100/200
        self.assertEqual(files[0].index, 3)  # 取自 id

    def test_contract_no_sdk_leak(self):
        import app.chain as chain_pkg
        chain_src = Path(chain_pkg.__file__).read_text(encoding="utf-8")
        self.assertNotIn("qbittorrentapi", chain_src)
        self.assertNotIn("transmission_rpc", chain_src)
        self.assertIn("Optional[List[DownloaderFile]]", chain_src)
        # 两个模块不再 import SDK 文件类型
        import app.modules.qbittorrent as q
        import app.modules.transmission as t
        self.assertNotIn("import TorrentFilesList", Path(q.__file__).read_text(encoding="utf-8"))
        self.assertNotIn("transmission_rpc import File", Path(t.__file__).read_text(encoding="utf-8"))
