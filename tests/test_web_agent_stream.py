import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app import schemas
from app.agent import ReplyMode
from app.api.endpoints.agent import (
    _WebAgentMoviePilotAgent,
    _build_web_agent_notification_events,
    _build_web_agent_session_id,
    _resolve_web_agent_choice_payload,
    _split_web_agent_output,
)
from app.helper.interaction import AgentInteractionOption, agent_interaction_manager
from app.schemas.message import ChannelCapability, ChannelCapabilityManager
from app.schemas.types import MessageChannel, NotificationType


def test_split_web_agent_output_extracts_verbose_tool_message():
    """应将啰嗦模式工具提示拆成独立工具事件。"""
    events = _split_web_agent_output("准备查询。\n\n⚙️ => 查询站点\n\n已完成")

    assert events == [
        {"type": "delta", "content": "准备查询。\n\n"},
        {"type": "tool", "message": "查询站点"},
        {"type": "delta", "content": "已完成"},
    ]


def test_split_web_agent_output_extracts_summary_tool_message():
    """应将非啰嗦模式工具汇总行拆成独立工具事件。"""
    events = _split_web_agent_output("（查询了 2 次数据）\n\n这里是结果")

    assert events == [
        {"type": "tool", "message": "查询了 2 次数据"},
        {"type": "delta", "content": "\n这里是结果"},
    ]


def test_split_web_agent_output_preserves_standalone_newline_delta():
    """独立换行增量应保留，避免流式 Markdown 列表被拼成同一行。"""
    chunks = [
        "可以这样操作：",
        "\n",
        "- **搜索资源**：搜索电影",
        "\n",
        "- **下载管理**：添加任务",
    ]
    content = ""

    for chunk in chunks:
        for event in _split_web_agent_output(chunk):
            if event["type"] == "delta":
                content += event["content"]

    assert content == "可以这样操作：\n- **搜索资源**：搜索电影\n- **下载管理**：添加任务"


def test_build_web_agent_session_id_is_stable_per_user_and_seed():
    """同一用户和前端会话标识应生成稳定的服务端会话 ID。"""
    user = SimpleNamespace(id=1, name="admin")

    first = _build_web_agent_session_id(user, "browser-session")
    second = _build_web_agent_session_id(user, "browser-session")
    other = _build_web_agent_session_id(user, "other-session")

    assert first == second
    assert first != other
    assert first.startswith("web-agent:")


def test_web_agent_admin_context_uses_current_user_id():
    """Web Agent 工具权限应按当前登录用户 ID 判断管理员身份。"""
    agent = _WebAgentMoviePilotAgent(
        session_id="web-agent:session",
        user_id="7",
        channel=MessageChannel.WebAgent.value,
        source="web-agent",
        username="normal-user",
        replay_mode=ReplyMode.CAPTURE_ONLY,
    )

    with patch("app.api.endpoints.agent.UserOper") as user_oper:
        user_oper.return_value.async_get_by_id = AsyncMock(
            return_value=SimpleNamespace(is_superuser=True)
        )

        assert asyncio.run(agent._is_system_admin_context()) is True
        user_oper.return_value.async_get_by_id.assert_awaited_once_with(7)


def test_web_agent_channel_supports_streaming_and_attachments():
    """WebAgent 渠道应声明流式、多媒体和文件发送能力。"""
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.INLINE_BUTTONS
    )
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.CALLBACK_QUERIES
    )
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.MESSAGE_EDITING
    )
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.IMAGES
    )
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.AUDIO_OUTPUT
    )
    assert ChannelCapabilityManager.supports_capability(
        MessageChannel.WebAgent, ChannelCapability.FILE_SENDING
    )


def test_build_web_agent_notification_events_extracts_image():
    """Agent 工具发送图片消息时应转换为图片附件事件。"""
    events = _build_web_agent_notification_events(
        schemas.Notification(
            channel=MessageChannel.WebAgent,
            mtype=NotificationType.Agent,
            title="海报",
            text="已找到图片",
            image="https://example.com/poster.jpg",
        )
    )

    assert events == [
        {"type": "delta", "content": "海报\n\n已找到图片"},
        {
            "type": "attachment",
            "attachment": {
                "kind": "image",
                "url": "https://example.com/poster.jpg",
                "download_url": "https://example.com/poster.jpg",
                "name": "海报",
                "mime_type": None,
            },
        },
    ]


def test_build_web_agent_notification_events_registers_local_file(tmp_path):
    """Agent 工具发送本地文件时应生成可下载附件事件。"""
    file_path = tmp_path / "report.txt"
    file_path.write_text("hello", encoding="utf-8")

    events = _build_web_agent_notification_events(
        schemas.Notification(
            channel=MessageChannel.WebAgent,
            mtype=NotificationType.Agent,
            file_path=str(file_path),
            file_name="report.txt",
        )
    )

    assert len(events) == 1
    attachment = events[0]["attachment"]
    assert events[0]["type"] == "attachment"
    assert attachment["kind"] == "file"
    assert attachment["name"] == "report.txt"
    assert attachment["mime_type"] == "text/plain"
    assert attachment["size"] == 5
    assert attachment["url"].startswith("message/agent/file/")


def test_build_web_agent_notification_events_extracts_choice_card():
    """Agent 按钮通知应转换为 Web 选择卡片事件而非普通文本。"""
    events = _build_web_agent_notification_events(
        schemas.Notification(
            channel=MessageChannel.WebAgent,
            mtype=NotificationType.Agent,
            title="需要你的选择",
            text="请选择要执行的操作",
            buttons=[
                [
                    {
                        "text": "继续下载",
                        "callback_data": "agent_interaction:choice:req-1:1",
                    }
                ],
                [
                    {
                        "text": "查看详情",
                        "callback_data": "agent_interaction:choice:req-1:2",
                    }
                ],
            ],
        )
    )

    assert events == [
        {
            "type": "choice",
            "choice": {
                "id": "req-1",
                "title": "需要你的选择",
                "prompt": "请选择要执行的操作",
                "buttons": [
                    {
                        "label": "继续下载",
                        "callback_data": "agent_interaction:choice:req-1:1",
                    },
                    {
                        "label": "查看详情",
                        "callback_data": "agent_interaction:choice:req-1:2",
                    },
                ],
            },
        }
    ]


def test_resolve_web_agent_choice_payload_returns_next_message():
    """Web 按钮回调应解析为下一条用户消息并返回卡片反馈。"""
    agent_interaction_manager.clear()
    request = agent_interaction_manager.create_request(
        session_id="web-agent:session",
        user_id="1",
        channel=MessageChannel.WebAgent.value,
        source="web-agent",
        username="admin",
        title="需要你的选择",
        prompt="请选择",
        options=[
            AgentInteractionOption(label="电影", value="我选择电影"),
            AgentInteractionOption(label="电视剧", value="我选择电视剧"),
        ],
    )

    try:
        result = _resolve_web_agent_choice_payload(
            callback_data=f"agent_interaction:choice:{request.request_id}:2",
            user_id="1",
        )
    finally:
        agent_interaction_manager.clear()

    assert result["message"] == "我选择电视剧"
    assert result["session_id"] == "web-agent:session"
    assert result["feedback"]["prompt"] == "请选择"
    assert result["feedback"]["selected_label"] == "电视剧"
