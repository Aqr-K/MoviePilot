from unittest.mock import AsyncMock, Mock, patch

from app.chain.message import MessageChain
from app.core.config import settings
from app.helper.interaction import AgentInteractionOption, agent_interaction_manager, media_interaction_manager
from app.schemas.types import MessageChannel


def test_explicit_ai_message_bypasses_pending_media_interaction():
    """显式 /ai 消息应绕过误触发的媒体交互状态并回到 Agent 会话。"""
    chain = MessageChain()
    media_interaction_manager.clear()
    media_interaction_manager.create_or_replace(
        user_id="10001",
        channel=MessageChannel.Wechat,
        source="wechat-test",
        username="tester",
        action="Search",
        keyword="确认",
        title="确认",
    )

    try:
        with patch.object(chain, "_record_user_message"), patch(
            "app.chain.message.MediaInteractionChain.handle_text_interaction",
            return_value=True,
        ) as handle_media_interaction, patch.object(
            chain, "_handle_ai_message", return_value=True
        ) as handle_ai_message:
            chain.handle_message(
                channel=MessageChannel.Wechat,
                source="wechat-test",
                userid="10001",
                username="tester",
                text="/ai 确认",
            )
    finally:
        media_interaction_manager.clear()

    handle_ai_message.assert_called_once()
    handle_media_interaction.assert_not_called()


def test_explicit_ai_message_is_not_recorded_to_message_history():
    """显式 /ai 消息不登记到数据库或实时消息队列。"""
    chain = MessageChain()

    with patch.object(settings, "AI_AGENT_ENABLE", True), patch.object(
        chain, "_record_user_message"
    ) as record_user_message, patch(
        "app.chain.message.agent_manager.process_message",
        new_callable=AsyncMock,
    ) as process_message, patch(
        "app.chain.message.asyncio.run_coroutine_threadsafe",
        side_effect=lambda coro, _loop: (coro.close(), Mock())[1],
    ):
        chain.handle_message(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            text="/ai 帮我检查订阅",
        )

    record_user_message.assert_not_called()
    process_message.assert_called_once()


def test_agent_choice_callback_is_not_recorded_to_message_history():
    """Agent 按钮选择回传不登记到数据库或实时消息队列。"""
    chain = MessageChain()
    request = agent_interaction_manager.create_request(
        session_id="session-choice",
        user_id="10001",
        channel=MessageChannel.Telegram.value,
        source="telegram-test",
        username="tester",
        title="需要你的选择",
        prompt="请选择",
        options=[
            AgentInteractionOption(label="电影", value="我选择电影"),
            AgentInteractionOption(label="电视剧", value="我选择电视剧"),
        ],
    )

    try:
        with patch.object(settings, "AI_AGENT_ENABLE", True), patch.object(
            chain, "_record_user_message"
        ) as record_user_message, patch.object(
            chain, "edit_message", return_value=True
        ), patch(
            "app.chain.message.agent_manager.process_message",
            new_callable=AsyncMock,
        ) as process_message, patch(
            "app.chain.message.asyncio.run_coroutine_threadsafe",
            side_effect=lambda coro, _loop: (coro.close(), Mock())[1],
        ):
            chain._handle_callback(
                text=f"CALLBACK:agent_interaction:choice:{request.request_id}:1",
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                original_message_id=123,
                original_chat_id="456",
            )
    finally:
        agent_interaction_manager.clear()

    record_user_message.assert_not_called()
    process_message.assert_called_once()
