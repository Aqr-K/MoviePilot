from unittest.mock import patch

import pytest

from app.chain.message import MediaInteractionChain, MessageChain
from app.core.context import Context, MediaInfo, TorrentInfo
from app.core.meta import MetaBase
from app.helper.interaction import media_interaction_manager
from app.schemas import TransferDirectoryConf
from app.schemas.types import MediaType, MessageChannel


@pytest.fixture(autouse=True)
def clear_media_interactions():
    """清理媒体交互状态，避免用例之间共享内存会话。"""
    yield
    media_interaction_manager.clear()


def _build_meta(name: str) -> MetaBase:
    """构造媒体识别元数据。"""
    meta = MetaBase(name)
    meta.name = name
    meta.begin_season = 1
    return meta


def _build_context(title: str = "星际穿越") -> Context:
    """构造可用于媒体交互下载测试的资源上下文。"""
    return Context(
        meta_info=_build_meta(title),
        media_info=MediaInfo(
            type=MediaType.MOVIE,
            title=title,
            year="2014",
            tmdb_id=1,
        ),
        torrent_info=TorrentInfo(
            title=f"{title}.2014.1080p",
            site_name="TestSite",
            enclosure="https://example.com/demo.torrent",
            seeders=10,
        ),
    )


def _build_tv_context(title: str = "葬送的芙莉莲") -> Context:
    """构造可用于媒体交互下载测试的电视剧上下文。"""
    return Context(
        meta_info=_build_meta(title),
        media_info=MediaInfo(
            type=MediaType.TV,
            title=title,
            year="2023",
            tmdb_id=2,
            category="动漫",
        ),
        torrent_info=TorrentInfo(
            title=f"{title}.S01.1080p",
            site_name="TestSite",
            enclosure="https://example.com/demo-tv.torrent",
            seeders=10,
        ),
    )


def _build_download_dirs() -> list[TransferDirectoryConf]:
    """构造消息交互可选择的下载目录配置。"""
    return [
        TransferDirectoryConf(
            name="电影下载",
            storage="local",
            download_path="/downloads/movies",
            priority=1,
            media_type=MediaType.MOVIE.value,
        ),
        TransferDirectoryConf(
            name="动画下载",
            storage="rclone",
            download_path="/media/anime",
            priority=2,
            media_type=MediaType.TV.value,
            media_category="动漫",
        ),
    ]


def test_message_routes_text_reply_to_media_interaction_before_ai():
    """已有传统媒体交互时，用户回复应优先交给传统交互处理。"""
    chain = MessageChain()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Wechat,
        source="wechat-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[MediaInfo(title="星际穿越", year="2014")],
    )
    assert request is not None

    with patch.object(chain, "_record_user_message"), patch(
        "app.chain.message.MediaInteractionChain.handle_text_interaction",
        return_value=True,
    ) as handle_text, patch.object(chain, "_handle_ai_message") as handle_ai:
        chain.handle_message(
            channel=MessageChannel.Wechat,
            source="wechat-test",
            userid="10001",
            username="tester",
            text="1",
        )

    handle_text.assert_called_once()
    handle_ai.assert_not_called()


def test_noai_prefix_starts_traditional_search_when_global_ai_enabled():
    """全局 AI 开启时，/noai 前缀应让本条消息进入传统搜索交互。"""
    chain = MessageChain()
    meta = _build_meta("星际穿越")
    medias = [
        MediaInfo(title="星际穿越", year="2014"),
        MediaInfo(title="Interstellar", year="2014"),
    ]

    with patch.object(chain, "_record_user_message"), patch(
        "app.chain.message.settings.AI_AGENT_ENABLE", True
    ), patch(
        "app.chain.message.settings.AI_AGENT_GLOBAL", True
    ), patch(
        "app.chain.media.MediaChain.search",
        return_value=(meta, medias),
    ) as search_media, patch(
        "app.chain.message.MediaInteractionChain.post_medias_message"
    ) as post_medias_message, patch.object(
        chain, "_handle_ai_message"
    ) as handle_ai:
        chain.handle_message(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            text="/noai 星际穿越",
        )

    search_media.assert_called_once_with("星际穿越")
    post_medias_message.assert_called_once()
    handle_ai.assert_not_called()

    request = media_interaction_manager.get_by_user("10001")
    assert request is not None
    assert request.action == "Search"
    assert request.keyword == "星际穿越"
    assert len(request.items) == 2


def test_noai_prefix_preserves_traditional_interaction_priority_after_search():
    """通过 /noai 进入传统交互后，后续选择应继续优先走传统交互。"""
    chain = MessageChain()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Wechat,
        source="wechat-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[MediaInfo(title="星际穿越", year="2014")],
    )
    assert request is not None

    with patch.object(chain, "_record_user_message"), patch(
        "app.chain.message.settings.AI_AGENT_ENABLE", True
    ), patch(
        "app.chain.message.settings.AI_AGENT_GLOBAL", True
    ), patch(
        "app.chain.message.MediaInteractionChain.handle_text_interaction",
        return_value=True,
    ) as handle_text, patch.object(chain, "_handle_ai_message") as handle_ai:
        chain.handle_message(
            channel=MessageChannel.Wechat,
            source="wechat-test",
            userid="10001",
            username="tester",
            text="1",
        )

    handle_text.assert_called_once()
    handle_ai.assert_not_called()


def test_callback_routes_to_media_interaction_chain():
    """媒体按钮回调应路由到媒体交互链。"""
    chain = MessageChain()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[MediaInfo(title="星际穿越", year="2014")],
    )

    with patch(
        "app.chain.message.MediaInteractionChain.handle_callback_interaction",
        return_value=True,
    ) as handle_callback:
        chain._handle_callback(
            text=f"CALLBACK:media:{request.request_id}:page-next",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
        )

    handle_callback.assert_called_once()


def test_media_interaction_starts_search_and_posts_media_list():
    """传统媒体交互应能搜索媒体并发送候选列表。"""
    chain = MediaInteractionChain()
    meta = _build_meta("星际穿越")
    medias = [
        MediaInfo(title="星际穿越", year="2014"),
        MediaInfo(title="Interstellar", year="2014"),
    ]

    with patch(
        "app.chain.media.MediaChain.search",
        return_value=(meta, medias),
    ), patch.object(chain, "post_medias_message") as post_medias_message:
        handled = chain.handle_text_interaction(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            text="星际穿越",
        )

    assert handled
    post_medias_message.assert_called_once()
    notification = post_medias_message.call_args.args[0]
    assert notification.save_history is False
    assert notification.buttons
    assert notification.buttons[0][0]["callback_data"].startswith("media:")

    request = media_interaction_manager.get_by_user("10001")
    assert request is not None
    assert request.action == "Search"
    assert len(request.items) == 2


def test_media_interaction_legacy_page_callback_updates_existing_request():
    """旧格式翻页回调仍应更新当前媒体交互请求。"""
    chain = MediaInteractionChain()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[
            MediaInfo(title=f"资源 {index}", year="2024")
            for index in range(1, 11)
        ],
    )

    with patch.object(chain, "post_medias_message") as post_medias_message:
        handled = chain.handle_callback_interaction(
            callback_data="page_n",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            original_message_id=123,
            original_chat_id="456",
        )

    assert handled
    assert request.page == 1
    post_medias_message.assert_called_once()
    notification = post_medias_message.call_args.args[0]
    assert notification.original_message_id == 123
    assert notification.original_chat_id == "456"


def test_torrent_selection_prompts_download_dir_buttons_before_download():
    """支持按钮的渠道选择资源后，应先发送下载目录按钮而不是立即下载。"""
    chain = MediaInteractionChain()
    context = _build_context()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )
    request.phase = "torrent"

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ), patch.object(chain, "post_message") as post_message, patch(
        "app.chain.message.DownloadChain.download_single"
    ) as download_single:
        handled = chain.handle_text_interaction(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            text="1",
        )

    assert handled
    download_single.assert_not_called()
    assert request.phase == "download-dir"
    post_message.assert_called_once()
    notification = post_message.call_args.args[0]
    assert notification.save_history is False
    assert "请选择下载目录" in notification.title
    assert "1. 自动匹配目录" in notification.text
    assert "2. 电影下载 (/downloads/movies)" in notification.text
    assert "动画下载" not in notification.text
    assert notification.buttons[0][0]["callback_data"] == f"media:{request.request_id}:download-dir:1"


def test_torrent_selection_prompts_text_download_dir_for_plain_channel():
    """不支持按钮的渠道选择资源后，应提示用户回复数字选择下载目录。"""
    chain = MediaInteractionChain()
    context = _build_context()
    request = media_interaction_manager.create_or_replace(
        user_id="wechat-user",
        channel=MessageChannel.Wechat,
        source="wechat-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )
    request.phase = "torrent"

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ), patch.object(chain, "post_message") as post_message:
        handled = chain.handle_text_interaction(
            channel=MessageChannel.Wechat,
            source="wechat-test",
            userid="wechat-user",
            username="tester",
            text="1",
        )

    assert handled
    notification = post_message.call_args.args[0]
    assert notification.save_history is False
    assert "请回复对应数字" in notification.title
    assert notification.buttons is None
    assert "1. 自动匹配目录" in notification.text
    assert "2. 电影下载 (/downloads/movies)" in notification.text
    assert "动画下载" not in notification.text


def test_download_dir_callback_runs_pending_single_download_without_save_path_for_auto():
    """下载目录选择自动匹配时，应不传 save_path 继续执行挂起的单资源下载。"""
    chain = MediaInteractionChain()
    context = _build_context()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )
    request.phase = "download-dir"
    request.pending_download_mode = "single"
    request.pending_download_context = context

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ), patch(
        "app.chain.message.DownloadChain.download_single",
        return_value="hash",
    ) as download_single:
        request.download_dirs = chain._get_download_dirs(context.media_info)
        handled = chain.handle_callback_interaction(
            callback_data=f"media:{request.request_id}:download-dir:1",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
        )

    assert handled
    assert request.phase == "torrent"
    download_single.assert_called_once()
    assert download_single.call_args.args[0] is context
    assert download_single.call_args.kwargs["save_path"] is None


def test_download_dir_callback_runs_pending_single_download_with_save_path():
    """下载目录按钮回调应使用所选 save_path 继续执行挂起的单资源下载。"""
    chain = MediaInteractionChain()
    context = _build_context()
    request = media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )
    request.phase = "download-dir"
    request.pending_download_mode = "single"
    request.pending_download_context = context

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ), patch(
        "app.chain.message.DownloadChain.download_single",
        return_value="hash",
    ) as download_single:
        request.download_dirs = chain._get_download_dirs(context.media_info)
        handled = chain.handle_callback_interaction(
            callback_data=f"media:{request.request_id}:download-dir:2",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
        )

    assert handled
    assert request.phase == "torrent"
    download_single.assert_called_once()
    assert download_single.call_args.args[0] is context
    assert download_single.call_args.kwargs["save_path"] == "/downloads/movies"


def test_download_dir_text_reply_runs_pending_single_download_without_save_path():
    """下载目录文本回复选择自动匹配时应不传 save_path。"""
    chain = MediaInteractionChain()
    context = _build_context()
    request = media_interaction_manager.create_or_replace(
        user_id="wechat-user",
        channel=MessageChannel.Wechat,
        source="wechat-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )
    request.phase = "download-dir"
    request.pending_download_mode = "single"
    request.pending_download_context = context

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ), patch(
        "app.chain.message.DownloadChain.download_single",
        return_value="hash",
    ) as download_single:
        request.download_dirs = chain._get_download_dirs()
        handled = chain.handle_text_interaction(
            channel=MessageChannel.Wechat,
            source="wechat-test",
            userid="wechat-user",
            username="tester",
            text="1",
        )

    assert handled
    assert request.phase == "torrent"
    download_single.assert_called_once()
    assert download_single.call_args.args[0] is context
    assert download_single.call_args.kwargs["save_path"] is None


def test_get_download_dirs_keeps_matching_tv_category_dir():
    """目录列表应保留匹配当前电视剧类别的下载目录。"""
    chain = MediaInteractionChain()
    context = _build_tv_context()

    with patch(
        "app.chain.message.DirectoryHelper.get_download_dirs",
        return_value=_build_download_dirs(),
    ):
        download_dirs = chain._get_download_dirs(context.media_info)

    assert [download_dir.name for download_dir in download_dirs] == [
        "自动匹配目录",
        "动画下载",
    ]
    assert download_dirs[1].save_path == "rclone:/media/anime"
