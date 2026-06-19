from types import SimpleNamespace
from typing import Iterator, Optional

import pytest

from app.agent.tools.base import MoviePilotTool
from app.agent.tools.factory import MoviePilotToolFactory
from app.core.plugin import PluginManager
from app.utils.singleton import Singleton


class DemoAgentTool(MoviePilotTool):
    """测试用插件工具。"""

    name: str = "demo_agent_tool"
    description: str = "Demo agent tool for tests."

    async def run(self, **kwargs) -> str:
        """返回测试结果。"""
        return "ok"


class DemoMessageAgentTool(DemoAgentTool):
    """测试用消息发送插件工具。"""

    name: str = "demo_message_agent_tool"
    sends_message: bool = True


@pytest.fixture
def plugin_manager() -> Iterator[PluginManager]:
    """构造隔离的插件管理器实例，避免单例缓存污染其它用例。"""
    Singleton._instances.pop((PluginManager, (), frozenset()), None)
    manager = PluginManager()
    yield manager
    Singleton._instances.pop((PluginManager, (), frozenset()), None)


def _build_plugin(
    tools: list[type[MoviePilotTool]],
    state: bool = True,
    calls: Optional[list[int]] = None,
) -> SimpleNamespace:
    """构造仅包含 Agent 工具接口的插件实例。"""

    def get_agent_tools() -> list[type[MoviePilotTool]]:
        """返回测试预设的工具类列表。"""
        if calls is not None:
            calls.append(1)
        return tools

    return SimpleNamespace(
        plugin_name="Demo Plugin",
        get_state=lambda: state,
        get_agent_tools=get_agent_tools,
    )


def test_plugin_agent_tools_are_cached(plugin_manager: PluginManager) -> None:
    """插件智能体工具注册表应缓存，避免同一轮启动反复询问插件实例。"""
    calls: list[int] = []
    plugin_manager.running_plugins["DemoPlugin"] = _build_plugin(
        [DemoAgentTool], calls=calls
    )

    first_result = plugin_manager.get_plugin_agent_tools()
    second_result = plugin_manager.get_plugin_agent_tools()

    assert len(calls) == 1
    assert first_result == second_result
    assert first_result[0]["tools"] == [DemoAgentTool]


def test_plugin_agent_tools_cache_returns_copy(plugin_manager: PluginManager) -> None:
    """缓存命中时应返回副本，调用方修改结果不应污染注册表缓存。"""
    plugin_manager.running_plugins["DemoPlugin"] = _build_plugin([DemoAgentTool])

    first_result = plugin_manager.get_plugin_agent_tools()
    first_result[0]["tools"].append(DemoMessageAgentTool)

    second_result = plugin_manager.get_plugin_agent_tools()

    assert second_result[0]["tools"] == [DemoAgentTool]


def test_plugin_agent_tools_cache_can_be_cleared(
    plugin_manager: PluginManager,
) -> None:
    """清理缓存后应重新读取插件当前声明的智能体工具。"""
    tools = [DemoAgentTool]
    calls: list[int] = []
    plugin_manager.running_plugins["DemoPlugin"] = _build_plugin(tools, calls=calls)

    assert plugin_manager.get_plugin_agent_tools()[0]["tools"] == [DemoAgentTool]
    tools.append(DemoMessageAgentTool)
    assert plugin_manager.get_plugin_agent_tools()[0]["tools"] == [DemoAgentTool]

    plugin_manager.clear_plugin_agent_tools_cache()

    assert plugin_manager.get_plugin_agent_tools()[0]["tools"] == [
        DemoAgentTool,
        DemoMessageAgentTool,
    ]
    assert len(calls) == 2


def test_factory_reuses_plugin_registry_but_creates_new_tool_instances(
    plugin_manager: PluginManager,
) -> None:
    """工具工厂可复用插件注册表缓存，但每次请求仍需创建新的工具实例。"""
    calls: list[int] = []
    plugin_manager.running_plugins["DemoPlugin"] = _build_plugin(
        [DemoAgentTool], calls=calls
    )

    first_tools = MoviePilotToolFactory.create_tools(
        session_id="session-1",
        user_id="10001",
    )
    second_tools = MoviePilotToolFactory.create_tools(
        session_id="session-2",
        user_id="10002",
    )

    first_demo_tool = next(tool for tool in first_tools if tool.name == "demo_agent_tool")
    second_demo_tool = next(tool for tool in second_tools if tool.name == "demo_agent_tool")

    assert len(calls) == 1
    assert first_demo_tool is not second_demo_tool
    assert first_demo_tool._session_id == "session-1"
    assert second_demo_tool._session_id == "session-2"


def test_factory_suppresses_plugin_message_tools_for_subagents(
    plugin_manager: PluginManager,
) -> None:
    """子代理静默工具列表不应包含会直接向用户发消息的插件工具。"""
    plugin_manager.running_plugins["DemoPlugin"] = _build_plugin(
        [DemoAgentTool, DemoMessageAgentTool]
    )

    tools = MoviePilotToolFactory.create_tools(
        session_id="session-1",
        user_id="10001",
        allow_message_tools=False,
    )
    tool_names = {tool.name for tool in tools}

    assert "demo_agent_tool" in tool_names
    assert "demo_message_agent_tool" not in tool_names
