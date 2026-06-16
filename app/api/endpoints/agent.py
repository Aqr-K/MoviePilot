import asyncio
import hashlib
import json
import mimetypes
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, StreamingResponse

from app import schemas
from app.agent import MoviePilotAgent, ReplyMode, StreamingHandler
from app.core.config import global_vars, settings
from app.db.models import User
from app.db.user_oper import get_current_active_superuser
from app.log import logger
from app.schemas.types import MessageChannel

router = APIRouter()

WEB_AGENT_SESSION_PREFIX = "web-agent:"
WEB_AGENT_SOURCE = "web-agent"
WEB_AGENT_FILE_TTL_SECONDS = 6 * 60 * 60
WEB_AGENT_FILE_MAX_ITEMS = 256
_WEB_AGENT_FILE_REGISTRY: dict[str, dict[str, Any]] = {}


class _WebAgentStreamingHandler(StreamingHandler):
    """
    Web 前端专用流式处理器，将工具提示和文本统一回调给 SSE。
    """

    def __init__(self, on_emit: Callable[[str], None]) -> None:
        super().__init__()
        self._on_emit = on_emit

    def emit(self, token: str) -> str:
        """追加 token 并同步通知 SSE 生产者。"""
        emitted = super().emit(token)
        if emitted:
            self._on_emit(emitted)
        return emitted

    def flush_pending_tool_summary(self) -> str:
        """输出延迟聚合的工具摘要。"""
        emitted = super().flush_pending_tool_summary()
        if emitted:
            self._on_emit(emitted)
        return ""

    async def start_streaming(
        self,
        channel: Optional[str] = None,
        source: Optional[str] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        original_message_id: Optional[str] = None,
        original_chat_id: Optional[str] = None,
        title: str = "",
    ) -> None:
        """Web SSE 自身负责外发，不启动消息模块编辑循环。"""
        self._channel = channel
        self._source = source
        self._user_id = user_id
        self._username = username
        self._original_message_id = original_message_id
        self._original_chat_id = original_chat_id
        self._title = title
        self._streaming_enabled = True
        self._sent_text = ""
        self._message_response = None
        self._msg_start_offset = 0
        self._pending_tool_stats = {}

    async def stop_streaming(self) -> tuple[bool, str]:
        """停止 Web SSE 流式状态，保留缓冲区给 Agent 收口逻辑去重。"""
        if not self._streaming_enabled:
            return False, ""
        self._streaming_enabled = False
        self.flush_pending_tool_summary()
        with self._lock:
            self._sent_text = ""
            self._message_response = None
            self._msg_start_offset = 0
            self._pending_tool_stats = {}
        return False, ""

    @property
    def is_auto_flushing(self) -> bool:
        """让工具执行提示进入缓冲区，由 SSE 回调负责外发。"""
        return True


class _WebAgentMoviePilotAgent(MoviePilotAgent):
    """
    Web 前端专用 Agent，强制使用流式推理。
    """

    def __init__(
        self,
        *args: Any,
        notification_callback: Optional[Callable[[schemas.Notification], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._notification_callback = notification_callback
        self.stream_handler = _WebAgentStreamingHandler(self._emit_output)

    def _should_stream(self) -> bool:
        """Web 面板需要实时输出，即使 Web 渠道本身不支持消息编辑。"""
        return True

    async def _is_system_admin_context(self) -> bool:
        """Web Agent 入口已要求超级管理员，工具上下文可直接按管理员处理。"""
        return True

    async def _build_tool_context(self, should_dispatch_reply: bool) -> dict[str, object]:
        """向工具上下文注入 Web SSE 通知回调。"""
        context = await super()._build_tool_context(should_dispatch_reply)
        context["notification_callback"] = self._notification_callback
        return context

    def _handle_stream_text(self, text: str) -> None:
        """文本输出交由 Web 流式处理器统一回调，避免重复增量。"""
        self.stream_handler.emit(text)


def _build_web_agent_session_id(user: User, session_id: Optional[str]) -> str:
    """
    构建前端 Agent 会话 ID。

    :param user: 当前登录用户
    :param session_id: 前端传入的会话标识
    :return: 可用于 Agent 记忆隔离的服务端会话 ID
    """
    seed = str(session_id or "").strip() or uuid.uuid4().hex
    user_part = user.name or str(user.id)
    digest = hashlib.sha256(f"{user_part}:{seed}".encode("utf-8")).hexdigest()
    return f"{WEB_AGENT_SESSION_PREFIX}{digest[:32]}"


def _build_web_agent_sse(event_type: str, data: Optional[dict] = None) -> str:
    """
    构建 Web Agent SSE 消息。

    :param event_type: 前端事件类型
    :param data: 事件数据
    :return: 符合 SSE 格式的字符串
    """
    payload = {"type": event_type, **(data or {})}
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _cleanup_web_agent_file_registry() -> None:
    """清理过期或过量的 Web Agent 临时附件引用。"""
    now = time.time()
    expired_ids = [
        file_id
        for file_id, info in _WEB_AGENT_FILE_REGISTRY.items()
        if now - info.get("created_at", now) > WEB_AGENT_FILE_TTL_SECONDS
    ]
    for file_id in expired_ids:
        _WEB_AGENT_FILE_REGISTRY.pop(file_id, None)

    overflow = len(_WEB_AGENT_FILE_REGISTRY) - WEB_AGENT_FILE_MAX_ITEMS
    if overflow <= 0:
        return
    sorted_items = sorted(
        _WEB_AGENT_FILE_REGISTRY.items(),
        key=lambda item: item[1].get("created_at", 0),
    )
    for file_id, _ in sorted_items[:overflow]:
        _WEB_AGENT_FILE_REGISTRY.pop(file_id, None)


def _guess_web_agent_attachment_kind(
    mime_type: Optional[str], fallback: str = "file"
) -> str:
    """
    根据 MIME 类型推断前端附件展示方式。

    :param mime_type: 文件 MIME 类型
    :param fallback: 无法推断时使用的类型
    :return: image、audio 或 file
    """
    if mime_type and mime_type.startswith("image/"):
        return "image"
    if mime_type and mime_type.startswith("audio/"):
        return "audio"
    return fallback


def _build_web_agent_url_attachment(
    url: str,
    kind: str,
    name: Optional[str] = None,
    mime_type: Optional[str] = None,
) -> dict:
    """
    构建远程或 data URL 附件事件。

    :param url: 前端可访问的附件地址
    :param kind: 附件展示类型
    :param name: 展示名称
    :param mime_type: MIME 类型
    :return: 前端附件描述
    """
    return {
        "kind": kind,
        "url": url,
        "download_url": url,
        "name": name,
        "mime_type": mime_type,
    }


def _register_web_agent_file(
    file_path: Optional[str],
    file_name: Optional[str] = None,
    kind: Optional[str] = None,
) -> Optional[dict]:
    """
    注册 Web Agent 本地附件并返回前端可访问的短期下载地址。

    :param file_path: 本地文件路径
    :param file_name: 前端展示文件名
    :param kind: 附件展示类型
    :return: 前端附件描述，文件不可访问时返回 None
    """
    if not file_path:
        return None
    try:
        resolved_path = Path(file_path).expanduser().resolve(strict=True)
    except OSError:
        return None
    if not resolved_path.is_file():
        return None

    _cleanup_web_agent_file_registry()
    file_id = uuid.uuid4().hex
    display_name = file_name or resolved_path.name
    mime_type = mimetypes.guess_type(display_name or str(resolved_path))[0]
    file_url = f"message/agent/file/{file_id}"
    _WEB_AGENT_FILE_REGISTRY[file_id] = {
        "path": resolved_path,
        "name": display_name,
        "mime_type": mime_type or "application/octet-stream",
        "created_at": time.time(),
    }
    return {
        "kind": kind or _guess_web_agent_attachment_kind(mime_type),
        "url": file_url,
        "download_url": file_url,
        "name": display_name,
        "mime_type": mime_type,
        "size": resolved_path.stat().st_size,
    }


def _build_web_agent_notification_events(
    notification: schemas.Notification,
) -> list[dict]:
    """
    将 Agent 工具通知转换为 Web SSE 事件。

    :param notification: 工具产生的通知消息
    :return: 前端可直接应用到当前助手消息的事件列表
    """
    events = []
    text_parts = [
        str(item).strip()
        for item in (notification.title, notification.text)
        if str(item or "").strip()
    ]
    if text_parts:
        events.append({"type": "delta", "content": "\n\n".join(text_parts)})

    if notification.image:
        image_ref = notification.image
        image_path = Path(image_ref).expanduser()
        attachment = None
        if not image_ref.startswith(("http://", "https://", "data:", "blob:")):
            attachment = _register_web_agent_file(
                image_ref, file_name=Path(image_ref).name, kind="image"
            )
        if not attachment:
            attachment = _build_web_agent_url_attachment(
                image_ref,
                kind="image",
                name=notification.title or image_path.name or "image",
            )
        events.append({"type": "attachment", "attachment": attachment})

    if notification.voice_path:
        attachment = _register_web_agent_file(
            notification.voice_path,
            file_name=Path(notification.voice_path).name,
            kind="audio",
        )
        if attachment:
            events.append({"type": "attachment", "attachment": attachment})

    if notification.file_path:
        attachment = _register_web_agent_file(
            notification.file_path,
            file_name=notification.file_name or Path(notification.file_path).name,
        )
        if attachment:
            events.append({"type": "attachment", "attachment": attachment})

    return events


def _split_web_agent_output(text: str) -> list[dict]:
    """
    将 Agent 输出拆成普通文本与工具提示事件。

    :param text: 本次新增的 Agent 文本
    :return: 前端可直接渲染的事件片段
    """
    if not text:
        return []

    events = []

    def append_text(content: str) -> None:
        """将工具汇总行从普通文本中拆出，便于前端独立展示。"""
        if not content or not content.strip():
            return
        lines = content.splitlines(keepends=True)
        buffer = ""
        for line in lines:
            stripped_line = line.strip()
            if (
                stripped_line.startswith("（")
                and stripped_line.endswith("）")
            ):
                if buffer:
                    events.append({"type": "delta", "content": buffer})
                    buffer = ""
                events.append(
                    {
                        "type": "tool",
                        "message": stripped_line.strip("（）"),
                    }
                )
            else:
                buffer += line
        if buffer:
            events.append({"type": "delta", "content": buffer})

    marker = "⚙️ => "
    remaining = text
    while remaining:
        marker_index = remaining.find(marker)
        if marker_index < 0:
            append_text(remaining)
            break

        if marker_index > 0:
            append_text(remaining[:marker_index])

        after_marker = remaining[marker_index + len(marker):]
        line_end = after_marker.find("\n")
        if line_end < 0:
            message = after_marker.strip()
            remaining = ""
        else:
            message = after_marker[:line_end].strip()
            remaining = after_marker[line_end:].lstrip("\n")

        if message:
            events.append({"type": "tool", "message": message})

    return events


@router.get("/file/{file_id}", summary="下载 Web 智能助手附件")
async def download_web_agent_file(file_id: str) -> FileResponse:
    """
    下载 Web 智能助手本轮生成的临时附件。

    :param file_id: 附件随机标识
    :return: 附件文件响应
    """
    _cleanup_web_agent_file_registry()
    file_info = _WEB_AGENT_FILE_REGISTRY.get(file_id)
    if not file_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="附件不存在或已过期")

    file_path = file_info["path"]
    if not file_path.exists() or not file_path.is_file():
        _WEB_AGENT_FILE_REGISTRY.pop(file_id, None)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="附件不存在或已过期")

    return FileResponse(
        path=file_path,
        media_type=file_info.get("mime_type") or "application/octet-stream",
        filename=file_info.get("name") or file_path.name,
    )


@router.post("/stream", summary="Web智能助手流式对话")
async def web_agent_stream(
    payload: schemas.AgentWebChatRequest,
    request: Request,
    current_user: User = Depends(get_current_active_superuser),
) -> StreamingResponse:
    """
    Web 智能助手流式对话。

    :param payload: 对话请求
    :param request: 当前 HTTP 请求
    :param current_user: 当前登录管理员
    :return: SSE 流式响应
    """
    if not settings.AI_AGENT_ENABLE:
        return StreamingResponse(
            iter([
                _build_web_agent_sse(
                    "error",
                    {"message": "智能助手未启用，请先在系统设置中开启。"},
                )
            ]),
            media_type="text/event-stream",
        )

    prompt = payload.text.strip()
    if not prompt:
        return StreamingResponse(
            iter([
                _build_web_agent_sse(
                    "error",
                    {"message": "请输入要发送给智能助手的内容。"},
                )
            ]),
            media_type="text/event-stream",
        )

    session_id = _build_web_agent_session_id(current_user, payload.session_id)
    event_queue: asyncio.Queue = asyncio.Queue()
    last_output = ""

    def output_callback(output: str) -> None:
        """
        接收 Agent 累积输出并转成增量事件。
        """
        nonlocal last_output
        delta = output[len(last_output):] if output.startswith(last_output) else output
        last_output = output
        for item in _split_web_agent_output(delta):
            event_queue.put_nowait(item)

    def notification_callback(notification: schemas.Notification) -> None:
        """
        接收 Agent 工具主动发送的 Web 通知。
        """
        for item in _build_web_agent_notification_events(notification):
            event_queue.put_nowait(item)

    async def event_generator() -> AsyncIterator[str]:
        """
        生成前端 Agent SSE 事件。
        """
        files = [
            file.model_dump(exclude_none=True)
            for file in (payload.files or [])
        ]
        for audio_ref in payload.audio_refs or []:
            files.append({"ref": audio_ref, "mime_type": "audio/*"})

        agent = _WebAgentMoviePilotAgent(
            session_id=session_id,
            user_id=str(current_user.id),
            channel=MessageChannel.WebAgent.value,
            source=WEB_AGENT_SOURCE,
            username=current_user.name,
            replay_mode=ReplyMode.CAPTURE_ONLY,
            persist_output_message=False,
            allow_message_tools=True,
            output_callback=output_callback,
            notification_callback=notification_callback,
        )

        async def run_agent() -> None:
            """后台执行 Agent，并将结果写入事件队列。"""
            try:
                await agent.process(
                    message=prompt,
                    images=payload.images or [],
                    files=files or None,
                    has_audio_input=bool(payload.audio_refs),
                )
            except Exception as err:
                logger.error(f"Web智能助手执行失败: {str(err)}")
                await event_queue.put(
                    {"type": "error", "message": f"智能助手执行失败: {str(err)}"}
                )
            finally:
                await event_queue.put({"type": "done"})

        task = asyncio.create_task(run_agent())
        try:
            yield _build_web_agent_sse(
                "start",
                {"session_id": payload.session_id or session_id},
            )
            while not global_vars.is_system_stopped:
                if await request.is_disconnected():
                    break
                event = await event_queue.get()
                yield _build_web_agent_sse(event.pop("type"), event)
                if task.done() and event_queue.empty():
                    break
        except asyncio.CancelledError:
            return
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            await agent.cleanup()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
