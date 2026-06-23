import asyncio
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app.agent.middleware.activity_log import (
    ActivityLogMiddleware,
    QUERY_ACTIVITY_LOG_TOOL_DESCRIPTION,
    QUERY_ACTIVITY_LOG_TOOL_NAME,
    _summarize_with_llm,
    load_activity_log_index,
    query_activity_logs,
)
from app.agent.tools.factory import MoviePilotToolFactory
from app.agent.tools.tags import ToolTag


def _write_activity_log(activity_dir, date_str: str, lines: list[str]) -> None:
    """写入测试用活动日志。"""
    activity_dir.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    (activity_dir / f"{date_str}.md").write_text(
        f"# {date_str} 活动日志\n\n{body}\n",
        encoding="utf-8",
    )


def test_activity_log_index_counts_entries_without_body(tmp_path):
    """活动日志索引只应包含条目数量，不暴露完整摘要正文。"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    _write_activity_log(
        tmp_path,
        date_str,
        [
            "- **10:00** 帮用户整理了电影文件",
            "- **11:00** 查询了下载任务状态",
        ],
    )

    index = load_activity_log_index(str(tmp_path), days=1)

    assert index == {date_str: "2 条活动记录"}
    assert "整理了电影文件" not in json.dumps(index, ensure_ascii=False)


def test_activity_log_prompt_injects_index_not_full_log(tmp_path):
    """ActivityLogMiddleware 注入系统提示词时不应携带完整活动日志正文。"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    _write_activity_log(
        tmp_path,
        date_str,
        ["- **10:00** 这是一条不应默认进入上下文的活动正文"],
    )
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path), prompt_load_days=1)
    state_update = asyncio.run(middleware.abefore_agent({}, runtime=None))
    request = SimpleNamespace(
        state=state_update,
        system_message=SystemMessage(content="SYSTEM"),
        override=lambda **kwargs: SimpleNamespace(
            state=state_update,
            system_message=kwargs.get("system_message", SystemMessage(content="SYSTEM")),
        ),
    )

    modified = middleware.modify_request(request)
    system_text = str(modified.system_message.content)

    assert "1 条活动记录" in system_text
    assert "这是一条不应默认进入上下文的活动正文" not in system_text
    assert "query_activity_log" in system_text


def test_activity_log_abefore_agent_refreshes_existing_state(tmp_path):
    """复用 Agent 图时，活动日志索引仍应在每轮执行前刷新。"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path), prompt_load_days=1)
    state = {"activity_log_contents": {"old": "旧索引"}}

    _write_activity_log(
        tmp_path,
        date_str,
        ["- **10:00** 新增活动记录"],
    )
    state_update = asyncio.run(middleware.abefore_agent(state, runtime=None))

    assert state_update == {"activity_log_contents": {date_str: "1 条活动记录"}}


def test_activity_log_skips_trivial_greeting_without_llm(tmp_path):
    """无实际任务的寒暄不应调用 LLM，也不应写入活动日志。"""
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path))
    summarize_mock = AsyncMock(return_value="不应写入")
    append_mock = AsyncMock()

    with (
        patch(
            "app.agent.middleware.activity_log._summarize_with_llm",
            new=summarize_mock,
        ),
        patch.object(middleware, "_append_activity", new=append_mock),
    ):
        asyncio.run(
            middleware.aafter_agent(
                {
                    "messages": [
                        HumanMessage(content="你好"),
                        AIMessage(content="你好，有什么可以帮你？"),
                    ],
                },
                runtime=None,
            )
        )

    summarize_mock.assert_not_awaited()
    append_mock.assert_not_awaited()
    assert not list(tmp_path.glob("*.md"))


def test_summarize_with_llm_ignores_skip_marker():
    """LLM 返回 SKIP 时应视为无需记录活动日志。"""
    llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(content="SKIP"))
    )

    with patch(
        "app.agent.llm.LLMHelper.get_llm",
        new=AsyncMock(return_value=llm),
    ):
        summary = asyncio.run(_summarize_with_llm("用户: 你好"))

    assert summary is None
    llm.ainvoke.assert_awaited_once()


def test_activity_log_records_detailed_summary(tmp_path):
    """有实际工具动作的交互应写入较完整的活动摘要。"""
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path))
    summary = (
        "用户要求整理 `/downloads/Show`，助手调用 transfer_file 识别并转移剧集，"
        "结果成功写入目标媒体库。"
    )

    with patch(
        "app.agent.middleware.activity_log._summarize_with_llm",
        new=AsyncMock(return_value=summary),
    ):
        asyncio.run(
            middleware.aafter_agent(
                {
                    "messages": [
                        HumanMessage(content="帮我整理 /downloads/Show"),
                        AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": "transfer_file",
                                    "args": {"path": "/downloads/Show"},
                                    "id": "call_1",
                                }
                            ],
                        ),
                        ToolMessage(
                            content='{"success": true, "target": "/media/Show"}',
                            tool_call_id="call_1",
                        ),
                    ],
                },
                runtime=None,
            )
        )

    log_files = list(tmp_path.glob("*.md"))
    assert len(log_files) == 1
    content = log_files[0].read_text(encoding="utf-8")
    assert summary in content
    assert "- **" in content


def test_query_activity_logs_filters_by_keyword_and_date(tmp_path):
    """活动日志查询应支持日期和关键词过滤。"""
    _write_activity_log(
        tmp_path,
        "2026-06-18",
        [
            "- **10:00** 帮用户整理了电影 A",
            "- **10:30** 查询了站点状态",
        ],
    )
    _write_activity_log(
        tmp_path,
        "2026-06-17",
        ["- **09:00** 帮用户整理了电影 B"],
    )

    payload = query_activity_logs(
        str(tmp_path),
        keyword="整理",
        date="2026-06-18",
        limit=10,
    )

    assert payload["success"] is True
    assert payload["total_count"] == 1
    assert payload["entries"][0]["date"] == "2026-06-18"
    assert payload["entries"][0]["time"] == "10:00"
    assert payload["entries"][0]["summary"] == "帮用户整理了电影 A"


def test_query_activity_logs_supports_optional_regex(tmp_path):
    """活动日志查询应在显式开启时支持正则匹配。"""
    _write_activity_log(
        tmp_path,
        "2026-06-18",
        [
            "- **10:00** 帮用户整理了剧集 A",
            "- **10:30** 查询了站点状态",
        ],
    )

    payload = query_activity_logs(
        str(tmp_path),
        keyword="整理|站点",
        use_regex=True,
        date="2026-06-18",
        limit=10,
    )

    assert payload["success"] is True
    assert payload["use_regex"] is True
    assert payload["total_count"] == 2


def test_query_activity_logs_reports_invalid_regex(tmp_path):
    """活动日志查询遇到无效正则时应返回结构化错误。"""
    payload = query_activity_logs(
        str(tmp_path),
        keyword="[",
        use_regex=True,
        date="2026-06-18",
    )

    assert payload["success"] is False
    assert "无效的活动日志正则表达式" in payload["message"]
    assert payload["entries"] == []


def test_activity_log_middleware_exposes_query_tool(tmp_path):
    """ActivityLogMiddleware 应以中间件工具形式暴露活动日志查询。"""
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path))

    assert [tool.name for tool in middleware.tools] == [QUERY_ACTIVITY_LOG_TOOL_NAME]
    assert ToolTag.Read in middleware.tools[0].tags
    assert ToolTag.System in middleware.tools[0].tags
    assert "recent MoviePilot Agent activity logs" in middleware.tools[0].description


def test_activity_log_middleware_query_tool_returns_json_payload(tmp_path):
    """query_activity_log 中间件工具应返回结构化 JSON 查询结果。"""
    _write_activity_log(
        tmp_path,
        "2026-06-18",
        ["- **10:00** 帮用户整理了电影 A"],
    )
    middleware = ActivityLogMiddleware(activity_dir=str(tmp_path))
    tool = middleware.tools[0]

    result = asyncio.run(
        tool.ainvoke({"keyword": "整理", "date": "2026-06-18", "limit": 5})
    )

    payload = json.loads(result)
    assert payload["success"] is True
    assert payload["returned_count"] == 1
    assert payload["entries"][0]["summary"] == "帮用户整理了电影 A"


def test_activity_log_tool_call_records_streaming_summary(tmp_path):
    """query_activity_log 工具执行时应记录流式聚合摘要。"""

    async def _run_test():
        calls = []
        stream_handler = SimpleNamespace(
            is_streaming=True,
            record_tool_call=lambda **kwargs: calls.append(kwargs),
        )
        middleware = ActivityLogMiddleware(
            activity_dir=str(tmp_path),
            stream_handler=stream_handler,
        )
        request = SimpleNamespace(
            tool=SimpleNamespace(name=QUERY_ACTIVITY_LOG_TOOL_NAME),
            tool_call={
                "args": {
                    "keyword": "整理",
                    "date": "2026-06-18",
                }
            },
        )

        async def _fake_handler(_request):
            """返回模拟工具结果。"""
            return "ok"

        result = await middleware.awrap_tool_call(request, _fake_handler)
        return result, calls

    result, calls = asyncio.run(_run_test())

    assert result == "ok"
    assert calls == [
        {
            "tool_name": QUERY_ACTIVITY_LOG_TOOL_NAME,
            "tool_message": QUERY_ACTIVITY_LOG_TOOL_DESCRIPTION,
            "tool_kwargs": {
                "keyword": "整理",
                "date": "2026-06-18",
            },
        }
    ]


def test_factory_does_not_register_activity_log_tool():
    """活动日志查询工具应由中间件注册，不应进入全局工具工厂。"""
    with patch(
        "app.agent.tools.factory.PluginManager.get_plugin_agent_tools",
        return_value=[],
    ):
        tools = MoviePilotToolFactory.create_tools(
            session_id="activity-session",
            user_id="10001",
        )

    tool_names = {tool.name for tool in tools}
    assert QUERY_ACTIVITY_LOG_TOOL_NAME not in tool_names
