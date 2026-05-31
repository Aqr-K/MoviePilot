import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from langchain_core.language_models.fake_chat_models import FakeListChatModel

import app.agent.middleware.subagents as subagent_module
from app.agent.middleware.subagents import (
    MoviePilotSubAgentMiddleware,
    SUBAGENT_TASK_TOOL_NAME,
    create_subagent_middlewares,
)
from app.agent.tools.tags import ToolTag


class TestAgentSubagents(unittest.TestCase):
    def test_create_subagent_middlewares_registers_task_tool(self):
        """子代理中间件应向主 Agent 注册 task 委派工具。"""
        model = FakeListChatModel(responses=["ok"])

        middlewares, task_tools = create_subagent_middlewares(
            model=model,
            tools=[],
            stream_handler=None,
        )

        self.assertEqual(len(middlewares), 2)
        self.assertEqual([tool.name for tool in task_tools], [SUBAGENT_TASK_TOOL_NAME])
        self.assertIn("media-researcher", task_tools[0].description)
        self.assertIn("system-diagnostician", task_tools[0].description)

    def test_subagent_tools_are_selected_by_tags(self):
        """子代理应根据工具标签筛选工具，而不是依赖工具名名单。"""
        model = FakeListChatModel(responses=["ok"])
        tools = [
            SimpleNamespace(
                name="custom_media_lookup",
                tags=[ToolTag.Read.value, ToolTag.Media.value],
            ),
            SimpleNamespace(
                name="custom_media_writer",
                tags=[ToolTag.Read.value, ToolTag.Write.value, ToolTag.Media.value],
            ),
            SimpleNamespace(
                name="custom_site_lookup",
                tags=[ToolTag.Read.value, ToolTag.Site.value],
            ),
        ]
        captured = {}

        def _fake_create_agent(**kwargs):
            captured.update(kwargs)
            return kwargs

        middleware = MoviePilotSubAgentMiddleware(
            model=model,
            profiles=subagent_module._builtin_subagent_profiles(),
            tools=tools,
        )

        with patch.object(subagent_module, "create_agent", side_effect=_fake_create_agent):
            middleware._get_agent("media-researcher")

        self.assertEqual(
            [tool.name for tool in captured["tools"]],
            ["custom_media_lookup"],
        )

    def test_builtin_tools_declare_tags_in_implementation(self):
        """所有内置工具实现都应显式声明 tags。"""
        impl_dir = Path(__file__).resolve().parents[1] / "app" / "agent" / "tools" / "impl"
        missing_tools = []
        for path in sorted(impl_dir.glob("*.py")):
            text = path.read_text()
            for block in text.split("\nclass "):
                if "(MoviePilotTool)" not in block:
                    continue
                class_name = block.split("(", 1)[0].strip()
                if "tags: list[str]" not in block:
                    missing_tools.append(f"{path.name}:{class_name}")

        self.assertEqual([], missing_tools)


if __name__ == "__main__":
    unittest.main()
