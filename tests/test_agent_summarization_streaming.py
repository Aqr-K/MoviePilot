import asyncio
from unittest.mock import patch

from langchain.agents.middleware import SummarizationMiddleware

import app.agent as agent_module
from app.agent.middleware.runtime_config import RuntimeConfigMiddleware


class _FakeLLM:
    _llm_type = "openai-chat"

    def __init__(self, model: str):
        self.model = model
        self.profile = {"max_input_tokens": 64000}


def test_streaming_agent_uses_non_streaming_llm_for_summary():
    """流式 Agent 的摘要中间件应使用非流式 LLM。"""
    agent = agent_module.MoviePilotAgent(session_id="session-1", user_id="10001")
    main_llm = _FakeLLM("main")
    non_streaming_llm = _FakeLLM("non-streaming")
    captured: dict = {}

    def _fake_create_agent(**kwargs):
        """捕获 create_agent 参数。"""
        captured.update(kwargs)
        return object()

    with (
        patch.object(
            agent, "_initialize_llm", side_effect=[main_llm, non_streaming_llm]
        ),
        patch.object(agent, "_initialize_tools", return_value=[]),
        patch.object(
            agent_module.prompt_manager, "get_agent_prompt", return_value="prompt"
        ),
        patch.object(
            agent_module, "create_subagent_middlewares", return_value=([], [])
        ),
        patch.object(agent_module, "create_agent", side_effect=_fake_create_agent),
        patch.object(agent_module.settings, "LLM_MAX_TOOLS", 0),
    ):
        asyncio.run(agent._create_agent(streaming=True))

    summary_middleware = next(
        middleware
        for middleware in captured["middleware"]
        if isinstance(middleware, SummarizationMiddleware)
    )

    assert captured["model"] is main_llm
    assert summary_middleware.model is non_streaming_llm


def test_streaming_agent_uses_non_streaming_llm_for_model_middlewares():
    """流式 Agent 的模型型中间件应使用非流式 LLM。"""
    agent = agent_module.MoviePilotAgent(session_id="session-1", user_id="10001")
    main_llm = _FakeLLM("main")
    non_streaming_llm = _FakeLLM("non-streaming")
    captured: dict = {}

    class _FakeToolSelectorMiddleware:
        """记录工具选择中间件初始化参数。"""

        def __init__(
            self,
            model,
            max_tools,
            always_include=None,
            selection_tools=None,
        ):
            """保存测试断言需要的参数。"""
            self.model = model
            self.max_tools = max_tools
            self.always_include = always_include or []
            self.selection_tools = selection_tools or []

    def _fake_create_agent(**kwargs):
        """捕获 create_agent 参数。"""
        captured.update(kwargs)
        return object()

    class _FakeTool:
        """测试用工具占位对象。"""

        def __init__(self, name: str):
            """保存工具名。"""
            self.name = name

    fake_tools = [
        _FakeTool("list_directory"),
        _FakeTool("write_file"),
        _FakeTool("read_file"),
        _FakeTool("edit_file"),
        _FakeTool("execute_command"),
        _FakeTool("search_media"),
    ]

    with (
        patch.object(
            agent, "_initialize_llm", side_effect=[main_llm, non_streaming_llm]
        ),
        patch.object(agent, "_initialize_tools", return_value=fake_tools),
        patch.object(
            agent_module.prompt_manager, "get_agent_prompt", return_value="prompt"
        ),
        patch.object(
            agent_module, "create_subagent_middlewares", return_value=([], [])
        ),
        patch.object(
            agent_module,
            "ToolSelectorMiddleware",
            _FakeToolSelectorMiddleware,
        ),
        patch.object(agent_module, "create_agent", side_effect=_fake_create_agent),
        patch.object(agent_module.settings, "LLM_MAX_TOOLS", 3),
    ):
        asyncio.run(agent._create_agent(streaming=True))

    tool_selector_middleware = next(
        middleware
        for middleware in captured["middleware"]
        if isinstance(middleware, _FakeToolSelectorMiddleware)
    )

    assert tool_selector_middleware.model is non_streaming_llm
    assert tool_selector_middleware.max_tools == 3
    assert tool_selector_middleware.always_include == [
        "list_directory",
        "write_file",
        "read_file",
        "edit_file",
        "execute_command",
        "skill",
    ]
    assert tool_selector_middleware.selection_tools[: len(fake_tools)] == fake_tools
    assert [
        getattr(tool, "name", None)
        for tool in tool_selector_middleware.selection_tools[len(fake_tools):]
    ] == ["skill"]


def test_non_streaming_agent_reuses_main_llm_for_summary():
    """非流式 Agent 的摘要中间件应复用主 LLM。"""
    agent = agent_module.MoviePilotAgent(session_id="session-1", user_id="10001")
    main_llm = _FakeLLM("main")
    captured: dict = {}

    def _fake_create_agent(**kwargs):
        """捕获 create_agent 参数。"""
        captured.update(kwargs)
        return object()

    with (
        patch.object(agent, "_initialize_llm", return_value=main_llm),
        patch.object(agent, "_initialize_tools", return_value=[]),
        patch.object(
            agent_module.prompt_manager, "get_agent_prompt", return_value="prompt"
        ),
        patch.object(
            agent_module, "create_subagent_middlewares", return_value=([], [])
        ),
        patch.object(agent_module, "create_agent", side_effect=_fake_create_agent),
        patch.object(agent_module.settings, "LLM_MAX_TOOLS", 0),
    ):
        asyncio.run(agent._create_agent(streaming=False))

    summary_middleware = next(
        middleware
        for middleware in captured["middleware"]
        if isinstance(middleware, SummarizationMiddleware)
    )

    assert captured["model"] is main_llm
    assert summary_middleware.model is main_llm


def test_agent_uses_runtime_config_middleware_instead_of_hooks():
    """Agent 应使用运行时配置中间件而不是旧 hooks。"""
    agent = agent_module.MoviePilotAgent(session_id="session-1", user_id="10001")
    main_llm = _FakeLLM("main")
    captured: dict = {}

    def _fake_create_agent(**kwargs):
        """捕获 create_agent 参数。"""
        captured.update(kwargs)
        return object()

    with (
        patch.object(agent, "_initialize_llm", return_value=main_llm),
        patch.object(agent, "_initialize_tools", return_value=[]),
        patch.object(
            agent_module.prompt_manager, "get_agent_prompt", return_value="prompt"
        ),
        patch.object(
            agent_module, "create_subagent_middlewares", return_value=([], [])
        ),
        patch.object(agent_module, "create_agent", side_effect=_fake_create_agent),
        patch.object(agent_module.settings, "LLM_MAX_TOOLS", 0),
    ):
        asyncio.run(agent._create_agent(streaming=False))

    assert any(
        isinstance(middleware, RuntimeConfigMiddleware)
        for middleware in captured["middleware"]
    )
    assert not any(
        type(middleware).__name__ == "AgentHooksMiddleware"
        for middleware in captured["middleware"]
    )
