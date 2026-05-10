import asyncio
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from langchain.agents.middleware.types import ModelRequest, ModelResponse
from langchain_core.messages import AIMessage

from app.agent.middleware.usage import UsageMiddleware
from app.chain.message import MessageChain
from app.schemas.types import MessageChannel


class TestAgentSessionStatus(unittest.TestCase):
    def test_usage_middleware_records_usage_metadata(self):
        snapshots = []
        middleware = UsageMiddleware(on_usage=snapshots.append)
        request = ModelRequest(
            model=SimpleNamespace(
                model="gpt-4o-mini", profile={"max_input_tokens": 128000}
            ),
            messages=[],
            state={},
            runtime=None,
        )
        response = ModelResponse(
            result=[
                AIMessage(
                    content="ok",
                    usage_metadata={
                        "input_tokens": 1200,
                        "output_tokens": 300,
                        "total_tokens": 1500,
                    },
                )
            ]
        )

        async def handler(_: ModelRequest):
            return response

        result = asyncio.run(middleware.awrap_model_call(request, handler))

        self.assertIs(result, response)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["model"], "gpt-4o-mini")
        self.assertEqual(snapshots[0]["context_window_tokens"], 128000)
        self.assertEqual(snapshots[0]["input_tokens"], 1200)
        self.assertEqual(snapshots[0]["output_tokens"], 300)
        self.assertEqual(snapshots[0]["total_tokens"], 1500)
        self.assertAlmostEqual(snapshots[0]["context_usage_ratio"], 1200 / 128000)

    def test_remote_session_status_sends_usage_summary(self):
        chain = MessageChain()
        chain._user_sessions["10001"] = ("session-1", datetime.now())
        status = {
            "session_id": "session-1",
            "model": "gpt-4o-mini",
            "context_window_tokens": 128000,
            "last_input_tokens": 1200,
            "last_output_tokens": 300,
            "last_total_tokens": 1500,
            "last_context_usage_ratio": 1200 / 128000,
            "total_input_tokens": 4500,
            "total_output_tokens": 1500,
            "total_tokens": 6000,
            "model_call_count": 4,
            "last_updated_at": "2026-04-26 12:34:56",
            "is_processing": True,
            "pending_messages": 2,
        }

        with (
            patch(
                "app.chain.message.agent_manager.get_session_status",
                return_value=status,
            ),
            patch.object(chain, "post_message") as post_message,
        ):
            chain.remote_session_status(
                channel=MessageChannel.Telegram,
                userid="10001",
                source="telegram-test",
            )

        notification = post_message.call_args.args[0]
        self.assertEqual(notification.title, "当前智能体会话状态")
        self.assertIn("session-1", notification.text)
        self.assertIn("gpt-4o-mini", notification.text)
        self.assertIn("1,200 / 128,000 (0.94%)", notification.text)
        self.assertIn("输入 4,500 / 输出 1,500 / 总计 6,000", notification.text)
        self.assertIn("运行中", notification.text)

    def test_remote_session_status_handles_missing_session(self):
        chain = MessageChain()

        with patch.object(chain, "post_message") as post_message:
            chain.remote_session_status(
                channel=MessageChannel.Telegram,
                userid="10001",
                source="telegram-test",
            )

        notification = post_message.call_args.args[0]
        self.assertEqual(notification.title, "您当前没有活跃的智能体会话")
