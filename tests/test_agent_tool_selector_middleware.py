import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace

from langchain_core.messages import HumanMessage


def _stub_module(name: str, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        sys.modules[name] = module
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


sys.modules.pop("app.agent.middleware.tool_selection", None)
_stub_module(
    "app.log",
    logger=SimpleNamespace(debug=lambda *args, **kwargs: None),
)

module_path = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "agent"
    / "middleware"
    / "tool_selection.py"
)
spec = importlib.util.spec_from_file_location("test_tool_selector_module", module_path)
tool_selector_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(tool_selector_module)


class _FakeBoundModel:
    def __init__(self, content):
        self.content = content
        self.messages = None

    def invoke(self, messages):
        self.messages = messages
        return SimpleNamespace(content=self.content)

    async def ainvoke(self, messages):
        self.messages = messages
        return SimpleNamespace(content=self.content)


class _FakeModel:
    def __init__(
        self,
        *,
        content='{"tools": ["calendar", "search"]}',
        model_name="deepseek-reasoner",
        base_url="https://api.deepseek.com",
    ):
        self.model_name = model_name
        self.openai_api_base = base_url
        self.bind_calls = []
        self.bound_model = _FakeBoundModel(content)

    def bind(self, **kwargs):
        self.bind_calls.append(kwargs)
        return self.bound_model


class _FakeRequest:
    def __init__(self, *, tools, messages, model):
        self.tools = tools
        self.messages = messages
        self.model = model

    def override(self, **kwargs):
        data = {
            "tools": self.tools,
            "messages": self.messages,
            "model": self.model,
        }
        data.update(kwargs)
        return _FakeRequest(**data)


class ToolSelectorMiddlewareTest(unittest.TestCase):
    def test_awrap_model_call_uses_json_mode_for_deepseek(self):
        middleware = tool_selector_module.MoviePilotToolSelectorMiddleware(max_tools=2)
        tools = [
            SimpleNamespace(name="search", description="Search for information"),
            SimpleNamespace(name="calendar", description="Manage events"),
            SimpleNamespace(name="translate", description="Translate text"),
        ]
        model = _FakeModel()
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我安排明天的行程并查天气")],
            model=model,
        )
        handled_requests = []

        async def handler(updated_request):
            handled_requests.append(updated_request)
            return updated_request

        result = asyncio.run(middleware.awrap_model_call(request, handler))

        self.assertEqual(
            model.bind_calls,
            [{"response_format": {"type": "json_object"}}],
        )
        self.assertEqual(
            [tool.name for tool in result.tools],
            ["search", "calendar"],
        )
        prompt = model.bound_model.messages[0]["content"]
        self.assertIn("Return the answer in JSON only.", prompt)
        self.assertIn('- search: Search for information', prompt)
        self.assertIn('- calendar: Manage events', prompt)
        self.assertEqual(len(handled_requests), 1)

    def test_normalize_selection_response_accepts_code_fence_json(self):
        middleware = tool_selector_module.MoviePilotToolSelectorMiddleware()
        response = SimpleNamespace(
            content=[
                {
                    "type": "text",
                    "text": '```json\n{"tools": ["search"]}\n```',
                }
            ]
        )

        normalized = middleware._normalize_selection_response(response)

        self.assertEqual(normalized, {"tools": ["search"]})


if __name__ == "__main__":
    unittest.main()
