"""模块装载全流程冒烟。

`ModuleManager.load_modules()` 会逐个实例化模块并调用 `init_module()`，失败的模块被
`try/except` 吞掉、只留一行错误日志，然后**静默缺席** `_running_modules`。因此扫描模块类
能通过、单元测试也能通过，而某个模块在真实启动时根本没上线。

本次重构改动最大的正是这条路径：存储由驱动升为模块（`init_module` 现在会调
`init_storage`）、四个族整体换了导入路径、豆瓣拆成两个模块。这里断言没有模块在装载中
出错，缺席的必须是被开关关掉的，而不是崩掉的。
"""
from typing import List, Tuple
from unittest.mock import patch

import pytest

from app.modules import _ModuleBase
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager


@pytest.fixture(scope="module")
def loaded() -> Tuple[ModuleManager, List[str]]:
    """
    真实走一遍模块装载，并收集其间的错误日志

    绕开 Singleton 元类以免污染同进程内的其它用例；事件总线打桩，避免注册全局解析器。

    :return: (模块管理器, 装载错误日志列表)
    """
    previous = contract._module_base  # noqa: SLF001
    contract.configure_module_base(_ModuleBase)
    errors: List[str] = []
    manager = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.eventmanager"), \
            patch("app.runtime.extensions.module_manager.logger") as module_logger:
        module_logger.error.side_effect = \
            lambda message, *_args, **_kwargs: errors.append(str(message))
        manager.__init__()
    yield manager, errors
    contract._module_base = previous  # noqa: SLF001


def test_no_module_fails_to_load(loaded):
    """没有模块在实例化或初始化时出错。"""
    _, errors = loaded

    assert [error for error in errors if "Load Moudle Error" in error] == []


def test_every_discovered_module_is_running_or_switched_off(loaded):
    """缺席运行态的模块必须是被开关关掉的，不能是崩掉的。"""
    manager, _ = loaded
    absent = set(manager._modules) - set(manager._running_modules)  # noqa: SLF001

    unexplained = []
    for module_id in sorted(absent):
        module_cls = manager._modules[module_id]  # noqa: SLF001
        try:
            switched_off = not manager.check_setting(module_cls().init_setting())
        except Exception as err:
            unexplained.append(f"{module_id} 实例化失败：{err}")
            continue
        if not switched_off:
            unexplained.append(f"{module_id} 开关是开的却没上线")

    assert unexplained == []


def test_each_module_family_has_its_members_running(loaded):
    """五个族的成员都进入运行态，搬迁没有让任何一族整体掉线。"""
    manager, _ = loaded
    running = set(manager._running_modules)  # noqa: SLF001
    expected = {
        "下载器": {"QbittorrentModule", "TransmissionModule", "RtorrentModule"},
        "媒体库": {"EmbyModule", "JellyfinModule", "PlexModule", "NavidromeModule",
                   "TrimeMediaModule", "UgreenModule", "ZSpaceModule"},
        "存储": {"LocalStorage", "AliPan", "U115Pan", "Rclone", "Alist", "AlistGo", "SMB"},
        "识别源": {"TheMovieDbModule", "DoubanModule", "DoubanMusicModule", "BangumiModule",
                   "AniListModule", "TheTvDbModule", "MusicBrainzModule", "TheAudioDbModule"},
    }

    missing = {family: sorted(members - running) for family, members in expected.items()
               if members - running}

    assert missing == {}


def test_the_capability_index_is_built_from_running_modules(loaded):
    """能力索引在真实装载后可用，且覆盖各族的核心能力。"""
    manager, _ = loaded

    index = manager.get_capability_index()

    assert "LocalStorage" in index["list"]
    assert "QbittorrentModule" in index["list_torrents"]
    assert "EmbyModule" in index["mediaserver_librarys"]
    assert "FanartModule" in index["metadata_img"]
    assert "TheTvDbModule" not in index.get("recognize_media", [])
