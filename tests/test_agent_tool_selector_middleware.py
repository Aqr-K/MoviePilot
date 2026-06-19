import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from langchain_core.messages import AIMessage, HumanMessage

from app.agent.middleware import tool_selection as tool_selector_module
from app.agent.tools.tags import ToolTag


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
    def __init__(self, *, tools, messages, model, state=None, runtime=None):
        self.tools = tools
        self.messages = messages
        self.model = model
        self.state = state if state is not None else {"messages": messages}
        self.runtime = runtime

    def override(self, **kwargs):
        data = {
            "tools": self.tools,
            "messages": self.messages,
            "model": self.model,
            "state": self.state,
            "runtime": self.runtime,
        }
        data.update(kwargs)
        return _FakeRequest(**data)


def _tool(name, description, tags=None):
    """构造测试用工具对象。"""
    return SimpleNamespace(name=name, description=description, tags=tags or [])


class ToolSelectorMiddlewareTest(unittest.TestCase):
    def test_awrap_model_call_uses_json_mode_for_deepseek(self):
        tools = [
            SimpleNamespace(name="search", description="Search for information"),
            SimpleNamespace(name="calendar", description="Manage events"),
            SimpleNamespace(name="translate", description="Translate text"),
        ]
        model = _FakeModel()
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=2,
            selection_tools=tools,
        )
        middleware.model = model
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我安排明天的行程并查天气")],
            model=model,
        )
        handled_requests = []

        async def handler(updated_request):
            handled_requests.append(updated_request)
            return updated_request

        state_update = asyncio.run(
            middleware.abefore_agent(request.state, runtime=None, config=None)
        )
        if state_update:
            request.state.update(state_update)
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
        self.assertIn("MoviePilot tool-chain hints:", prompt)
        self.assertEqual(len(handled_requests), 1)

    def test_awrap_model_call_reuses_first_selection_for_later_model_rounds(self):
        tools = [
            SimpleNamespace(name="search", description="Search for information"),
            SimpleNamespace(name="calendar", description="Manage events"),
            SimpleNamespace(name="translate", description="Translate text"),
        ]
        model = _FakeModel(content='{"tools": ["calendar", "search"]}')
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=2,
            selection_tools=tools,
        )
        middleware.model = model
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我安排明天的行程并查天气")],
            model=model,
        )
        handled_requests = []

        async def handler(updated_request):
            handled_requests.append(updated_request)
            return updated_request

        state_update = asyncio.run(
            middleware.abefore_agent(request.state, runtime=None, config=None)
        )
        if state_update:
            request.state.update(state_update)
        first_result = asyncio.run(middleware.awrap_model_call(request, handler))
        second_result = asyncio.run(middleware.awrap_model_call(request, handler))

        self.assertEqual(
            model.bind_calls,
            [{"response_format": {"type": "json_object"}}],
        )
        self.assertEqual(
            [tool.name for tool in first_result.tools],
            ["search", "calendar"],
        )
        self.assertEqual(
            [tool.name for tool in second_result.tools],
            ["search", "calendar"],
        )
        self.assertEqual(len(handled_requests), 2)

    def test_awrap_model_call_caches_non_deepseek_selection_too(self):
        tools = [
            SimpleNamespace(name="search", description="Search for information"),
            SimpleNamespace(name="calendar", description="Manage events"),
            SimpleNamespace(name="translate", description="Translate text"),
        ]
        model = _FakeModel(
            model_name="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
        )
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=2,
            selection_tools=tools,
        )
        middleware.model = model
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我安排明天的行程并查天气")],
            model=model,
        )

        async def handler(updated_request):
            return updated_request

        parent_calls = 0

        async def _fake_parent_awrap(self, request_arg, handler_arg):
            nonlocal parent_calls
            parent_calls += 1
            selected_request = request_arg.override(
                tools=[request_arg.tools[1], request_arg.tools[0]]
            )
            return await handler_arg(selected_request)

        with patch.object(
            tool_selector_module.LLMToolSelectorMiddleware,
            "awrap_model_call",
            _fake_parent_awrap,
        ):
            state_update = asyncio.run(
                middleware.abefore_agent(request.state, runtime=None, config=None)
            )
            if state_update:
                request.state.update(state_update)
            first_result = asyncio.run(middleware.awrap_model_call(request, handler))
            second_result = asyncio.run(middleware.awrap_model_call(request, handler))

        self.assertEqual(parent_calls, 1)
        self.assertEqual(
            [tool.name for tool in first_result.tools],
            ["calendar", "search"],
        )
        self.assertEqual(
            [tool.name for tool in second_result.tools],
            ["calendar", "search"],
        )

    def test_normalize_selection_response_accepts_code_fence_json(self):
        middleware = tool_selector_module.ToolSelectorMiddleware()
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

    def test_deepseek_selection_uses_recent_conversation_context(self):
        """多轮追问时工具筛选应看到上一轮用户需求和助手回复。"""
        tools = [
            _tool(
                "query_plugin_config",
                "Query plugin config",
                [ToolTag.Read, ToolTag.Plugin, ToolTag.Settings],
            ),
            _tool(
                "update_plugin_config",
                "Update plugin config",
                [ToolTag.Write, ToolTag.Plugin, ToolTag.Settings],
            ),
            _tool(
                "reload_plugin",
                "Reload plugin",
                [ToolTag.Write, ToolTag.Plugin],
            ),
        ]
        model = _FakeModel(content='{"tools": ["query_plugin_config"]}')
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=3,
            selection_tools=tools,
        )
        middleware.model = model
        request = _FakeRequest(
            tools=tools,
            messages=[
                HumanMessage(content="帮我检查插件 DemoPlugin 的配置"),
                AIMessage(content="我建议先查询插件配置，然后根据结果决定是否重载插件。"),
                HumanMessage(content="按你说的来"),
            ],
            model=model,
        )

        state_update = asyncio.run(
            middleware.abefore_agent(request.state, runtime=None, config=None)
        )

        user_message = model.bound_model.messages[1]
        self.assertEqual(
            state_update,
            {"selected_tool_names": ["query_plugin_config", "update_plugin_config", "reload_plugin"]},
        )
        self.assertIsInstance(user_message, HumanMessage)
        self.assertIn(
            "Recent conversation context for tool selection",
            user_message.content,
        )
        self.assertIn("帮我检查插件 DemoPlugin 的配置", user_message.content)
        self.assertIn("我建议先查询插件配置", user_message.content)
        self.assertIn("按你说的来", user_message.content)

    def test_single_turn_selection_keeps_original_user_message(self):
        """单轮对话不应额外包裹上下文提示。"""
        tools = [
            _tool("search", "Search for information", [ToolTag.Read, ToolTag.Web]),
            _tool("calendar", "Manage events", [ToolTag.Write]),
        ]
        model = _FakeModel(content='{"tools": ["search"]}')
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=2,
            selection_tools=tools,
        )
        middleware.model = model
        original_message = HumanMessage(content="帮我查一下最近的更新")
        request = _FakeRequest(
            tools=tools,
            messages=[original_message],
            model=model,
        )

        asyncio.run(middleware.abefore_agent(request.state, runtime=None, config=None))

        user_message = model.bound_model.messages[1]
        self.assertIs(user_message, original_message)
        self.assertNotIn(
            "Recent conversation context for tool selection",
            user_message.content,
        )

    def test_process_selection_response_completes_low_count_tool_group_by_tags(self):
        """筛选结果过少时应按已命中的工具标签组补齐同组工具。"""
        tools = [
            _tool(
                "search_media",
                "Search media",
                [ToolTag.Read, ToolTag.Media],
            ),
            _tool(
                "search_torrents",
                "Search torrents",
                [ToolTag.Read, ToolTag.Resource, ToolTag.Site, ToolTag.Media],
            ),
            _tool(
                "get_search_results",
                "Get results",
                [ToolTag.Read, ToolTag.Resource],
            ),
            _tool(
                "add_download_tasks",
                "Add downloads",
                [ToolTag.Write, ToolTag.Download, ToolTag.Resource],
            ),
            _tool(
                "query_download_tasks",
                "Query downloads",
                [ToolTag.Read, ToolTag.Download],
            ),
        ]
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=4,
            selection_tools=tools,
        )
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我下载流浪地球")],
            model=_FakeModel(),
        )

        result = middleware._process_selection_response(
            {"tools": ["search_torrents"]},
            available_tools=tools,
            valid_tool_names=[tool.name for tool in tools],
            request=request,
        )

        self.assertEqual(len(result.tools), 4)
        self.assertEqual(
            {tool.name for tool in result.tools},
            {
                "search_media",
                "search_torrents",
                "get_search_results",
                "add_download_tasks",
            },
        )

    def test_process_selection_response_keeps_high_count_selection(self):
        """筛选结果数量足够时不应额外补齐工具。"""
        tools = [
            SimpleNamespace(name="search_media", description="Search media"),
            SimpleNamespace(name="search_torrents", description="Search torrents"),
            SimpleNamespace(name="get_search_results", description="Get results"),
            SimpleNamespace(name="query_sites", description="Query sites"),
        ]
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=4,
            selection_tools=tools,
        )
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我下载流浪地球")],
            model=_FakeModel(),
        )

        result = middleware._process_selection_response(
            {
                "tools": [
                    "search_media",
                    "search_torrents",
                    "get_search_results",
                    "query_sites",
                ]
            },
            available_tools=tools,
            valid_tool_names=[tool.name for tool in tools],
            request=request,
        )

        self.assertEqual(
            [tool.name for tool in result.tools],
            [
                "search_media",
                "search_torrents",
                "get_search_results",
                "query_sites",
            ],
        )

    def test_process_selection_response_respects_max_tools_when_completing(self):
        """标签组补齐不应突破 max_tools 上限。"""
        tools = [
            _tool(
                "list_directory",
                "List directory",
                [ToolTag.Read, ToolTag.Directory, ToolTag.File],
            ),
            _tool(
                "query_directory_settings",
                "Query settings",
                [ToolTag.Read, ToolTag.Directory, ToolTag.Settings],
            ),
            _tool(
                "recognize_media",
                "Recognize media",
                [ToolTag.Read, ToolTag.Media],
            ),
            _tool(
                "transfer_file",
                "Transfer file",
                [ToolTag.Write, ToolTag.Transfer, ToolTag.Library, ToolTag.File],
            ),
        ]
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=2,
            selection_tools=tools,
        )
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="帮我整理这个目录")],
            model=_FakeModel(),
        )

        result = middleware._process_selection_response(
            {"tools": ["transfer_file"]},
            available_tools=tools,
            valid_tool_names=[tool.name for tool in tools],
            request=request,
        )

        self.assertEqual(len(result.tools), 2)
        self.assertEqual(
            {tool.name for tool in result.tools},
            {"transfer_file", "list_directory"},
        )

    def test_process_selection_response_ignores_generic_tags_when_completing(self):
        """通用权限标签不应被当作工具组使用。"""
        tools = [
            _tool("read_one", "Read one", [ToolTag.Read]),
            _tool("read_two", "Read two", [ToolTag.Read]),
            _tool("write_one", "Write one", [ToolTag.Write, ToolTag.Admin]),
        ]
        middleware = tool_selector_module.ToolSelectorMiddleware(
            max_tools=4,
            selection_tools=tools,
        )
        request = _FakeRequest(
            tools=tools,
            messages=[HumanMessage(content="查一下信息")],
            model=_FakeModel(),
        )

        result = middleware._process_selection_response(
            {"tools": ["read_one"]},
            available_tools=tools,
            valid_tool_names=[tool.name for tool in tools],
            request=request,
        )

        self.assertEqual([tool.name for tool in result.tools], ["read_one"])
