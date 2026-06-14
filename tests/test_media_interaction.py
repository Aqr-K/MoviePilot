from unittest.mock import patch

import pytest

from app.chain.message import MediaInteractionChain, MessageChain
from app.core.context import MediaInfo
from app.core.meta import MetaBase
from app.helper.interaction import media_interaction_manager
from app.schemas.types import MessageChannel


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
