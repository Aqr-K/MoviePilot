import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app import schemas
from app.agent import ReplyMode
from app.api.endpoints.agent import (
    _WebAgentMoviePilotAgent,
    _WEB_AGENT_FILE_REGISTRY,
    _apply_web_agent_display_event,
    _build_web_agent_input_attachments,
    _build_web_agent_notification_events,
    _build_web_agent_session_id,
    _prepare_web_agent_audio_attachment_path,
    _transcribe_web_agent_audio_refs,
    web_agent_stream,
    _resolve_web_agent_choice_payload,
    _split_web_agent_output,
)
from app.db.agentchat_oper import AgentChatOper
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


def test_build_web_agent_session_id_reuses_accessible_history():
    """传入已有历史会话 ID 时应直接复用，避免跨渠道继续对话丢上下文。"""
    user = SimpleNamespace(id=1, name="admin", is_superuser=True)
    AgentChatOper().save_display_messages(
        session_id="telegram-session",
        user_id="telegram-user",
        username="tester",
        channel=MessageChannel.Telegram.value,
        source="telegram-main",
        messages=[],
        title="Telegram 会话",
    )

    assert _build_web_agent_session_id(user, "telegram-session") == "telegram-session"


def test_apply_web_agent_display_event_updates_snapshot():
    """WebAgent SSE 事件应可聚合为服务端展示快照。"""
    message = {
        "id": "assistant-1",
        "role": "assistant",
        "content": "",
        "createdAt": 1,
        "status": "streaming",
        "tools": [],
        "attachments": [],
        "choices": [],
    }

    _apply_web_agent_display_event({"type": "delta", "content": "你好"}, message)
    _apply_web_agent_display_event({"type": "tool", "message": "查询订阅"}, message)
    _apply_web_agent_display_event(
        {
            "type": "attachment",
            "attachment": {"kind": "file", "url": "message/agent/file/a"},
        },
        message,
    )
    _apply_web_agent_display_event({"type": "done"}, message)

    assert message["content"] == "你好"
    assert message["status"] == "done"
    assert len(message["tools"]) == 1
    assert message["tools"][0]["message"] == "查询订阅"
    assert message["tools"][0]["status"] == "done"
    assert message["attachments"] == [{"kind": "file", "url": "message/agent/file/a"}]


def test_build_web_agent_input_attachments_marks_kinds():
    """WebAgent 用户输入附件应转换为可展示的附件记录。"""
    attachments = _build_web_agent_input_attachments(
        images=["data:image/png;base64,abc"],
        files=[
            {
                "ref": "message/agent/file/file-1",
                "name": "report.txt",
                "mime_type": "text/plain",
                "size": 5,
            }
        ],
        audio_refs=["message/agent/file/audio-1"],
    )

    assert [item["kind"] for item in attachments] == ["image", "file", "audio"]
    assert attachments[1]["name"] == "report.txt"


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


def test_build_web_agent_notification_events_registers_voice_attachment(tmp_path):
    """Agent 工具发送语音时应转换为可播放的音频附件事件。"""
    voice_path = tmp_path / "reply.wav"
    voice_path.write_bytes(b"wav-bytes")

    events = _build_web_agent_notification_events(
        schemas.Notification(
            channel=MessageChannel.WebAgent,
            mtype=NotificationType.Agent,
            text="你好",
            voice_path=str(voice_path),
        )
    )

    assert len(events) == 2
    assert events[0] == {"type": "delta", "content": "你好"}
    attachment = events[1]["attachment"]
    assert events[1]["type"] == "attachment"
    assert attachment["kind"] == "audio"
    assert attachment["name"] == "reply.wav"
    assert attachment["mime_type"] == "audio/wav"
    assert attachment["size"] == len(b"wav-bytes")
    assert attachment["url"].startswith("message/agent/file/")


def test_prepare_web_agent_audio_attachment_converts_unsupported_audio(tmp_path):
    """WebAgent 会把浏览器不稳定支持的语音格式转为 WAV 供面板播放。"""
    source_path = tmp_path / "reply.opus"
    source_path.write_bytes(b"opus-bytes")
    converted_path = tmp_path / "voice" / "reply_web_abcdef12.wav"

    with patch("app.api.endpoints.agent.shutil.which", return_value="/usr/bin/ffmpeg"), patch(
        "app.api.endpoints.agent.uuid.uuid4",
        return_value=SimpleNamespace(hex="abcdef1234567890"),
    ), patch("app.api.endpoints.agent.subprocess.run") as run:
        def write_converted_file(*args, **kwargs):
            converted_path.write_bytes(b"wav-bytes")
            return SimpleNamespace(returncode=0, stderr="")

        run.side_effect = write_converted_file
        with patch("app.api.endpoints.agent.settings", SimpleNamespace(TEMP_PATH=tmp_path)):
            output_path = _prepare_web_agent_audio_attachment_path(str(source_path))

    assert output_path == converted_path
    assert output_path.read_bytes() == b"wav-bytes"


def test_transcribe_web_agent_audio_refs_reads_registered_upload(tmp_path):
    """WebAgent 上传录音应从临时附件登记表读取并转写为文本。"""
    voice_path = tmp_path / "recording.webm"
    voice_path.write_bytes(b"webm-bytes")
    _WEB_AGENT_FILE_REGISTRY["audio-test"] = {
        "path": voice_path,
        "name": "recording.webm",
        "mime_type": "audio/webm",
        "created_at": time.time(),
    }

    try:
        with patch(
            "app.api.endpoints.agent.AgentCapabilityManager.is_audio_input_available",
            return_value=True,
        ), patch(
            "app.api.endpoints.agent.AgentCapabilityManager.transcribe_audio",
            return_value="帮我推荐一部电影",
        ) as transcribe_audio:
            transcript = _transcribe_web_agent_audio_refs(["message/agent/file/audio-test"])
    finally:
        _WEB_AGENT_FILE_REGISTRY.pop("audio-test", None)

    assert transcript == "帮我推荐一部电影"
    transcribe_audio.assert_called_once_with(
        content=b"webm-bytes",
        filename="recording.webm",
    )


def test_web_agent_stream_returns_error_when_voice_transcription_fails():
    """仅发送语音且转写失败时应直接返回错误事件。"""
    payload = schemas.AgentWebChatRequest(
        text="",
        session_id="browser-session",
        audio_refs=["message/agent/file/missing"],
    )
    request = SimpleNamespace()
    user = SimpleNamespace(id=1, name="admin")

    with patch("app.api.endpoints.agent.settings.AI_AGENT_ENABLE", True), patch(
        "app.api.endpoints.agent._transcribe_web_agent_audio_refs",
        return_value=None,
    ):
        response = asyncio.run(web_agent_stream(payload, request, user))
        body = "".join(asyncio.run(_collect_streaming_response(response)))

    assert "error" in body
    assert "语音识别失败" in body


async def _collect_streaming_response(response):
    """读取 StreamingResponse，便于断言 SSE 内容。"""
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk)
    return chunks


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
