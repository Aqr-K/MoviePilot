"""功能族与具体模块的归属锁。

一个功能族 = 一批被多个模块共同实现的方法名，它们构成可互换的契约。此前这层归属完全
隐式——靠方法名恰好撞上，没有任何地方声明「obtain_images 是一个契约，实现者是这 5 个」。
后果是模块可以悄悄加入或退出一个族而无人察觉，混合模块也无从判断该归位到哪个目录。

本表把归属显式化：新模块加入某族、模块被拆分或合并，都会让下表失配，必须显式改表。

拆分判据（三条同时满足才拆一个多族模块）：
  1. 领域实体不同（如音乐 vs 影视）
  2. 有独立的来源或类型标识（如 MediaSource.DoubanMusic）
  3. 模块内部已出现自建分发器（如 recognize_media 里按来源分流）
仅仅"实现了多个族的方法"不构成拆分理由——识别源的图片、NFO、搜索三个面是同一职责的
切面，拆开只会造出空壳模块。

存储族的契约在 StorageBase 上，不在各驱动的 __init__ 里，因此不出现在本表，
由 tests/test_builtin_storage_modules.py 单独锁定。
"""
import ast
import collections
import pathlib
from typing import Dict, Set, Tuple

# 模块契约方法，不参与功能族判定
LIFECYCLE_METHODS = frozenset({
    "init_module", "init_setting", "stop", "test", "get_name", "get_type", "get_subtype",
    "get_priority", "on_config_changed", "get_reload_name", "handle_config_changed",
    "scheduler_job", "clear_cache",
})

MODULES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "app" / "modules"

# 族包本身只做导出，模块类在其子包里
FAMILY_PACKAGES = frozenset({
    ".", "downloaders", "mediaservers", "notifications", "recognizers", "storages",
})

CONTRACT_FAMILIES: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "消息投递": (
        ("post_message",),
        ("notifications/discord", "notifications/feishu", "notifications/qqbot", "notifications/slack", "notifications/synologychat", "notifications/telegram", "notifications/vocechat", "notifications/webpush", "notifications/wechat", "notifications/wechatclawbot"),
    ),
    "消息解析与富文本": (
        ("message_parser", "post_medias_message", "post_torrents_message"),
        ("notifications/discord", "notifications/feishu", "notifications/qqbot", "notifications/slack", "notifications/synologychat", "notifications/telegram", "notifications/vocechat", "notifications/wechat", "notifications/wechatclawbot"),
    ),
    "媒体存在判定": (
        ("media_exists",),
        ("filemanager", "mediaservers/emby", "mediaservers/jellyfin", "mediaservers/navidrome", "mediaservers/plex", "mediaservers/trimemedia", "mediaservers/ugreen", "mediaservers/zspace"),
    ),
    "媒体库查询": (
        ("media_statistic", "mediaserver_iteminfo", "mediaserver_items", "mediaserver_items_count", "mediaserver_latest", "mediaserver_latest_images", "mediaserver_librarys", "mediaserver_play_url", "mediaserver_playing", "mediaserver_tv_episodes", "user_authenticate"),
        ("mediaservers/emby", "mediaservers/jellyfin", "mediaservers/navidrome", "mediaservers/plex", "mediaservers/trimemedia", "mediaservers/ugreen", "mediaservers/zspace"),
    ),
    "媒体识别": (
        ("recognize_media",),
        ("recognizers/anilist", "recognizers/bangumi", "recognizers/douban", "recognizers/doubanmusic", "recognizers/musicbrainz", "recognizers/theaudiodb", "recognizers/themoviedb"),
    ),
    "媒体库 Webhook 解析": (
        ("webhook_parser",),
        ("mediaservers/emby", "mediaservers/jellyfin", "mediaservers/plex", "mediaservers/trimemedia", "mediaservers/ugreen", "mediaservers/zspace"),
    ),
    "图片元数据": (
        ("metadata_img",),
        ("fanart", "recognizers/anilist", "recognizers/bangumi", "recognizers/douban", "recognizers/themoviedb"),
    ),
    "渠道命令注册": (
        ("register_commands",),
        ("notifications/discord", "notifications/slack", "notifications/telegram", "notifications/vocechat", "notifications/wechat"),
    ),
    "消息交互": (
        ("edit_message", "mark_message_processing_finished", "mark_message_processing_started", "send_direct_message"),
        ("notifications/discord", "notifications/feishu", "notifications/slack", "notifications/telegram"),
    ),
    "NFO 与媒体搜索": (
        ("metadata_nfo", "search_medias"),
        ("recognizers/anilist", "recognizers/bangumi", "recognizers/douban", "recognizers/themoviedb"),
    ),
    "下载器": (
        ("download", "downloader_info", "list_torrents", "remove_torrents", "set_torrents_tag", "start_torrents", "stop_torrents", "torrent_files", "transfer_completed", "update_torrent"),
        ("downloaders/qbittorrent", "downloaders/rtorrent", "downloaders/transmission"),
    ),
    "音乐元数据": (
        ("get_music_source", "music_album", "recognize_music", "search_music"),
        ("recognizers/doubanmusic", "recognizers/musicbrainz", "recognizers/theaudiodb"),
    ),
    "图片获取": (
        ("obtain_images",),
        ("fanart", "recognizers/douban", "recognizers/themoviedb"),
    ),
    "剧集ID查询": (
        ("mediaserver_season_episode_ids",),
        ("mediaservers/emby", "mediaservers/jellyfin", "mediaservers/plex"),
    ),
    "消息删除": (
        ("delete_message",),
        ("notifications/discord", "notifications/slack", "notifications/telegram"),
    ),
    "微信媒体下载": (
        ("download_wechat_image_to_data_url", "download_wechat_media_bytes"),
        ("notifications/wechat", "notifications/wechatclawbot"),
    ),
    "音乐艺人": (
        ("music_artist", "music_artist_albums"),
        ("recognizers/musicbrainz", "recognizers/theaudiodb"),
    ),
    "Tracker 查询": (
        ("get_torrent_trackers",),
        ("downloaders/qbittorrent", "downloaders/transmission"),
    ),
    "媒体库图片鉴权": (
        ("mediaserver_image_cookies",),
        ("mediaservers/trimemedia", "mediaservers/ugreen"),
    ),
    "人物搜索": (
        ("search_persons",),
        ("recognizers/douban", "recognizers/themoviedb"),
    ),
    "音乐专辑关联": (
        ("music_album_related",),
        ("recognizers/doubanmusic", "recognizers/theaudiodb"),
    ),
    "识别缓存更新": (
        ("update_recognize_cache",),
        ("recognizers/musicbrainz", "recognizers/themoviedb"),
    ),
}

def module_surfaces() -> Dict[str, Set[str]]:
    """
    扫描各模块类对外暴露的方法名

    :return: {模块目录: {方法名, ...}}
    """
    surfaces: Dict[str, Set[str]] = {}
    for init in sorted(MODULES_ROOT.rglob("__init__.py")):
        rel = init.relative_to(MODULES_ROOT).parent.as_posix()
        if rel in FAMILY_PACKAGES:
            continue
        for node in ast.parse(init.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {ast.unparse(base) for base in node.bases}
            if not any("ModuleBase" in base or "StorageBase" in base for base in bases):
                continue
            surfaces.setdefault(rel, set()).update(
                child.name for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not child.name.startswith("_")
                and child.name not in LIFECYCLE_METHODS
                and not child.name.startswith("async_")
            )
    return surfaces


def observed_families() -> Dict[Tuple[str, ...], Tuple[str, ...]]:
    """
    从源码实际推导出的功能族

    :return: {实现者元组: 共同实现的方法名元组}
    """
    implementers: Dict[str, Set[str]] = collections.defaultdict(set)
    for module, methods in module_surfaces().items():
        for method in methods:
            implementers[method].add(module)
    grouped: Dict[Tuple[str, ...], Set[str]] = collections.defaultdict(set)
    for method, modules in implementers.items():
        if len(modules) > 1:
            grouped[tuple(sorted(modules))].add(method)
    return {modules: tuple(sorted(methods)) for modules, methods in grouped.items()}


def declared_families() -> Dict[Tuple[str, ...], Tuple[str, ...]]:
    """
    本表声明的功能族

    :return: {实现者元组: 方法名元组}
    """
    return {members: methods for methods, members in CONTRACT_FAMILIES.values()}


def test_no_undeclared_family_exists():
    """出现未登记的功能族时必须显式改表，模块不得悄悄加入或退出某个族。"""
    undeclared = {members: methods for members, methods in observed_families().items()
                  if members not in declared_families()}

    assert undeclared == {}


def test_no_declared_family_is_stale():
    """表里登记的族必须仍然成立，模块拆分或删除后不得留下失效条目。"""
    observed = observed_families()
    stale = {members: methods for members, methods in declared_families().items()
             if members not in observed}

    assert stale == {}


def test_declared_methods_match_the_source():
    """每个族登记的方法集合必须与源码一致。"""
    observed = observed_families()
    mismatched = {members: (methods, observed[members])
                  for members, methods in declared_families().items()
                  if members in observed and methods != observed[members]}

    assert mismatched == {}


def test_a_module_never_mixes_two_domains():
    """豆瓣影视与豆瓣音乐分属不同模块，混合模块不得复现。"""
    surfaces = module_surfaces()

    assert "recognize_music" not in surfaces["recognizers/douban"]
    assert "search_music" not in surfaces["recognizers/douban"]
    assert "recognize_music" in surfaces["recognizers/doubanmusic"]
