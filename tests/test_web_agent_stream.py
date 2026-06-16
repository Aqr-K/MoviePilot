from types import SimpleNamespace

from app import schemas
from app.api.endpoints.agent import (
    _build_web_agent_session_id,
    _build_web_agent_notification_events,
    _split_web_agent_output,
)
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


def test_build_web_agent_session_id_is_stable_per_user_and_seed():
    """同一用户和前端会话标识应生成稳定的服务端会话 ID。"""
    user = SimpleNamespace(id=1, name="admin")

    first = _build_web_agent_session_id(user, "browser-session")
    second = _build_web_agent_session_id(user, "browser-session")
    other = _build_web_agent_session_id(user, "other-session")

    assert first == second
    assert first != other
    assert first.startswith("web-agent:")


def test_web_agent_channel_supports_streaming_and_attachments():
    """WebAgent 渠道应声明流式、多媒体和文件发送能力。"""
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
