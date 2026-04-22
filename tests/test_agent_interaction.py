import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.agent.prompt import prompt_manager
from app.agent.tools.factory import MoviePilotToolFactory
from app.agent.tools.impl.ask_user_choice import (
    AskUserChoiceTool,
    UserChoiceOptionInput,
)
from app.chain.interaction import (
    AgentInteractionOption,
    agent_interaction_manager,
)
from app.chain.message import MessageChain
from app.schemas.types import MessageChannel


class TestAgentInteraction(unittest.TestCase):
    def tearDown(self):
        agent_interaction_manager.clear()

    def test_prompt_injects_choice_tool_hint_only_for_button_channels(self):
        telegram_prompt = prompt_manager.get_agent_prompt(
            channel=MessageChannel.Telegram.value
        )
        wechat_prompt = prompt_manager.get_agent_prompt(
            channel=MessageChannel.Wechat.value
        )

        self.assertIn("ask_user_choice", telegram_prompt)
        self.assertNotIn("ask_user_choice", wechat_prompt)

    def test_factory_injects_choice_tool_only_for_button_channels(self):
        with patch(
            "app.agent.tools.factory.PluginManager.get_plugin_agent_tools",
            return_value=[],
        ):
            telegram_tools = MoviePilotToolFactory.create_tools(
                session_id="session-1",
                user_id="10001",
                channel=MessageChannel.Telegram.value,
                source="telegram-test",
                username="tester",
            )
            wechat_tools = MoviePilotToolFactory.create_tools(
                session_id="session-2",
                user_id="10001",
                channel=MessageChannel.Wechat.value,
                source="wechat-test",
                username="tester",
            )

        self.assertIn("ask_user_choice", [tool.name for tool in telegram_tools])
        self.assertNotIn("ask_user_choice", [tool.name for tool in wechat_tools])

    def test_choice_tool_sends_buttons_and_registers_pending_request(self):
        tool = AskUserChoiceTool(session_id="session-1", user_id="10001")
        tool.set_message_attr(
            channel=MessageChannel.Telegram.value,
            source="telegram-test",
            username="tester",
        )
        tool.set_agent_context(agent_context={})

        with patch(
            "app.agent.tools.impl.ask_user_choice.ToolChain.async_post_message",
            new=AsyncMock(),
        ) as async_post_message:
            result = asyncio.run(
                tool.run(
                    message="请选择要执行的操作",
                    options=[
                        UserChoiceOptionInput(label="继续下载", value="继续下载"),
                        UserChoiceOptionInput(label="先看详情", value="先看详情"),
                    ],
                    title="需要你的选择",
                )
            )

        self.assertIn("等待用户选择", result)
        self.assertTrue(tool._agent_context.get("user_reply_sent"))
        notification = async_post_message.await_args.args[0]
        self.assertEqual(notification.text, "请选择要执行的操作")
        self.assertEqual(len(notification.buttons[0]), 2)

        callback_data = notification.buttons[0][0]["callback_data"]
        _, _, request_id, option_index = callback_data.split(":")
        resolved = agent_interaction_manager.resolve(
            request_id, int(option_index), "10001"
        )
        self.assertIsNotNone(resolved)
        _, option = resolved
        self.assertEqual(option.value, "继续下载")

    def test_agent_interaction_callback_routes_selected_value_back_to_agent(self):
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

        with patch.object(chain, "_handle_ai_message") as handle_ai_message, patch.object(
            chain.messagehelper, "put"
        ) as message_put, patch.object(chain.messageoper, "add") as message_add, patch.object(
            chain, "edit_message", return_value=True
        ) as edit_message:
            chain._handle_callback(
                text=f"CALLBACK:agent_interaction:choice:{request.request_id}:1",
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                original_message_id=123,
                original_chat_id="456",
            )

        handle_ai_message.assert_called_once()
        edit_message.assert_called_once_with(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            message_id=123,
            chat_id="456",
            title="需要你的选择",
            text="请选择\n\n已选择：电影",
        )
        kwargs = handle_ai_message.call_args.kwargs
        self.assertEqual(kwargs["text"], "我选择电影")
        self.assertEqual(kwargs["session_id"], "session-choice")
        message_put.assert_called_once()
        message_add.assert_called_once()

    def test_legacy_agent_choice_callback_still_supported(self):
        chain = MessageChain()
        request = agent_interaction_manager.create_request(
            session_id="session-choice",
            user_id="10001",
            channel=MessageChannel.Telegram.value,
            source="telegram-test",
            username="tester",
            title=None,
            prompt="请选择",
            options=[AgentInteractionOption(label="电影", value="我选择电影")],
        )

        with patch.object(chain, "_handle_ai_message") as handle_ai_message, patch.object(
            chain.messagehelper, "put"
        ), patch.object(chain.messageoper, "add"):
            chain._handle_callback(
                text=f"CALLBACK:agent_choice:{request.request_id}:1",
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
            )

        handle_ai_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
