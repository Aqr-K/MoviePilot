"""pytest 全局引导：隔离 CONFIG_DIR、补 sites 垫片、建表、装载网络守卫。

引导与网络守卫均复用 ``app/testing`` 的共享 harness（与插件仓 conftest 同源），
引导逻辑只在 ``app/testing`` 维护一处。
"""
# 必须早于首个 import app.db（其在 import 期即按 CONFIG_PATH 连库）：prepare_backend 内部
# 先隔离 CONFIG_DIR、补 app.helper.sites 垫片，再建表。app/testing 仅依赖标准库、import 不连库，
# 故此处先 import 再调用是安全的。
from app.testing.bootstrap import prepare_backend

prepare_backend()

# 复用共享 autouse 网络守卫；同一实现亦供各插件仓 conftest import 复用，避免逐仓维护
from app.testing.network_guard import block_real_network  # noqa: E402,F401

# 已安装的真实下载器 SDK 须先于测试桩进入 sys.modules：部分测试以
# ``sys.modules.setdefault("qbittorrentapi", ...)`` 注入仅含 TorrentFilesList 的假模块供无该包的 CI 用；
# 若假桩在真包导入前先落位，会令 test_downloader_file_normalization 的
# ``from qbittorrentapi import TorrentDictionary`` 失败。已装环境下此处优先导入真包使桩 setdefault no-op，
# 未装环境走 except 由桩兜底。
for _downloader_sdk in ("qbittorrentapi", "transmission_rpc"):
    try:
        __import__(_downloader_sdk)
    except ImportError:
        pass
