import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.agent.tools.impl.add_subscribe import AddSubscribeTool


class TestAgentAddSubscribeTool(unittest.TestCase):
    def test_tv_subscription_without_season_reports_default_first_season(self):
        tool = AddSubscribeTool(session_id="session-1", user_id="10001")

        with patch(
            "app.agent.tools.impl.add_subscribe.SubscribeChain.async_add",
            new=AsyncMock(return_value=(1, "")),
        ):
            result = asyncio.run(
                tool.run(
                    title="Breaking Bad",
                    year="2008",
                    media_type="tv",
                )
            )

        self.assertIn("第1季", result)
        self.assertIn("默认按第一季订阅", result)


if __name__ == "__main__":
    unittest.main()
