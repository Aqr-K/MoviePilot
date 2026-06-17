import asyncio
import hashlib
import json
import mimetypes
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse

from app import schemas
from app.agent import MoviePilotAgent, ReplyMode, StreamingHandler
from app.agent.llm.capability import AgentCapabilityManager
from app.core.config import global_vars, settings
from app.db.models import User
from app.db.user_oper import UserOper, get_current_active_user
from app.helper.interaction import agent_interaction_manager
from app.log import logger
from app.schemas.types import MessageChannel

router = APIRouter()

WEB_AGENT_SESSION_PREFIX = "web-agent:"
WEB_AGENT_SOURCE = "web-agent"
WEB_AGENT_FILE_TTL_SECONDS = 6 * 60 * 60
WEB_AGENT_FILE_MAX_ITEMS = 256
WEB_AGENT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024
WEB_AGENT_UPLOAD_CHUNK_SIZE = 1024 * 1024
WEB_AGENT_BROWSER_AUDIO_SUFFIXES = {".aac", ".m4a", ".mp3", ".mp4", ".wav", ".wave"}
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
        """Web Agent 根据当前登录用户 ID 判断工具管理员上下文。"""
        if not self.user_id:
            return False
        try:
            user = await UserOper().async_get_by_id(int(self.user_id))
        except (TypeError, ValueError):
            return False
        except Exception as e:
            logger.error(f"检查 Web Agent 用户管理员身份失败: {e}")
            return False
        return bool(user and user.is_superuser)

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


def _sanitize_web_agent_upload_name(
    filename: Optional[str], mime_type: Optional[str] = None
) -> str:
    """
    规范化 Web Agent 上传文件名，避免路径穿越和空文件名。

    :param filename: 浏览器上传的原始文件名
    :param mime_type: 浏览器上报的 MIME 类型
    :return: 可安全落盘的文件名
    """
    name = Path(filename or "attachment").name.strip()
    safe_name = "".join(
        char for char in name if char.isalnum() or char in (" ", ".", "_", "-")
    ).strip(" .")
    if not safe_name:
        safe_name = "attachment"
    if "." not in safe_name:
        suffix = mimetypes.guess_extension(mime_type or "") or ""
        safe_name = f"{safe_name}{suffix}"
    return safe_name


def _get_web_agent_upload_dir(user: User, session_id: Optional[str]) -> Path:
    """
    计算当前 Web Agent 会话的临时附件目录。

    :param user: 当前登录用户
    :param session_id: 前端会话标识
    :return: 已创建的临时附件目录
    """
    server_session_id = _build_web_agent_session_id(user, session_id)
    safe_session_id = server_session_id.replace(":", "_")
    upload_dir = settings.TEMP_PATH / "agent_uploads" / safe_session_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


async def _save_web_agent_upload(upload_file: UploadFile, target_path: Path) -> int:
    """
    分块保存 Web Agent 上传文件，并限制单文件体积。

    :param upload_file: FastAPI 上传文件对象
    :param target_path: 目标落盘路径
    :return: 已写入的字节数
    """
    size = 0
    try:
        with target_path.open("wb") as output:
            while True:
                chunk = await upload_file.read(WEB_AGENT_UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > WEB_AGENT_UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="附件超过 32MB，无法发送给智能助手",
                    )
                output.write(chunk)
    except Exception:
        target_path.unlink(missing_ok=True)
        raise
    finally:
        await upload_file.close()
    return size


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
    mime_type: Optional[str] = None,
) -> Optional[dict]:
    """
    注册 Web Agent 本地附件并返回前端可访问的短期下载地址。

    :param file_path: 本地文件路径
    :param file_name: 前端展示文件名
    :param kind: 附件展示类型
    :param mime_type: 已知 MIME 类型
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
    resolved_mime_type = mime_type or mimetypes.guess_type(
        display_name or str(resolved_path)
    )[0]
    file_url = f"message/agent/file/{file_id}"
    _WEB_AGENT_FILE_REGISTRY[file_id] = {
        "path": resolved_path,
        "name": display_name,
        "mime_type": resolved_mime_type or "application/octet-stream",
        "created_at": time.time(),
    }
    return {
        "kind": kind or _guess_web_agent_attachment_kind(resolved_mime_type),
        "url": file_url,
        "download_url": file_url,
        "name": display_name,
        "mime_type": resolved_mime_type,
        "size": resolved_path.stat().st_size,
    }


def _get_web_agent_audio_mime_type(audio_path: Path) -> Optional[str]:
    """
    生成浏览器播放更友好的音频 MIME 类型。

    :param audio_path: 音频文件路径
    :return: 可用于 FileResponse/audio 标签的 MIME 类型
    """
    suffix = audio_path.suffix.lower()
    if suffix in {".wav", ".wave"}:
        return "audio/wav"
    if suffix == ".mp3":
        return "audio/mpeg"
    if suffix in {".m4a", ".mp4"}:
        return "audio/mp4"
    if suffix == ".aac":
        return "audio/aac"

    return mimetypes.guess_type(audio_path.name)[0]


def _prepare_web_agent_audio_attachment_path(voice_path: str) -> Path:
    """
    将 Agent 语音回复准备成 Web 面板可稳定播放的音频文件。

    部分 TTS provider 会生成 Opus/Ogg，桌面 Chromium 通常可播放，但 iOS/Safari
    兼容性不稳定；WebAgent 只在浏览器内播放，因此这里单独转成 WAV。
    """
    try:
        source_path = Path(voice_path).expanduser().resolve(strict=True)
    except OSError:
        return Path(voice_path)
    if source_path.suffix.lower() in WEB_AGENT_BROWSER_AUDIO_SUFFIXES:
        return source_path
    if not shutil.which("ffmpeg"):
        logger.warning("WebAgent 语音转 WAV 跳过：ffmpeg 不可用，path=%s", source_path)
        return source_path

    voice_dir = settings.TEMP_PATH / "voice"
    voice_dir.mkdir(parents=True, exist_ok=True)
    output_path = voice_dir / f"{source_path.stem}_web_{uuid.uuid4().hex[:8]}.wav"
    cmd = [
        "ffmpeg",
        "-y",
        "-i",
        str(source_path),
        "-ar",
        "24000",
        "-ac",
        "1",
        "-f",
        "wav",
        str(output_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0 or not output_path.exists():
        logger.warning(
            "WebAgent 语音转 WAV 失败，将回退原文件: returncode=%s, stderr=%s",
            result.returncode,
            (result.stderr or "").strip()[:500],
        )
        return source_path
    return output_path


def _get_web_agent_registered_file(ref: str) -> Optional[dict[str, Any]]:
    """
    根据前端附件引用读取 WebAgent 临时文件登记信息。

    :param ref: message/agent/file/{file_id} 形式的短期引用
    :return: 文件登记信息，引用无效或过期时返回 None
    """
    normalized_ref = (ref or "").strip()
    prefix = "message/agent/file/"
    if not normalized_ref.startswith(prefix):
        return None

    _cleanup_web_agent_file_registry()
    file_id = normalized_ref[len(prefix):].split("/", 1)[0]
    return _WEB_AGENT_FILE_REGISTRY.get(file_id)


def _transcribe_web_agent_audio_refs(audio_refs: list[str]) -> Optional[str]:
    """
    转写 WebAgent 上传的本地录音附件。

    Web 面板上传后的音频已经保存在短期文件登记表里，不能再像第三方渠道那样
    走模块下载逻辑；这里直接读取临时文件并调用当前音频输入 provider。
    """
    if not audio_refs:
        return None
    if not AgentCapabilityManager.is_audio_input_available():
        logger.warning("WebAgent 音频输入能力未配置或未启用，跳过语音识别")
        return None

    transcripts = []
    for audio_ref in audio_refs:
        file_info = _get_web_agent_registered_file(audio_ref)
        if not file_info:
            logger.warning("WebAgent 语音引用不存在或已过期: ref=%s", audio_ref)
            continue

        file_path = Path(file_info["path"])
        try:
            content = file_path.read_bytes()
        except OSError as err:
            logger.warning("WebAgent 语音文件读取失败: ref=%s, error=%s", audio_ref, err)
            continue

        transcript = AgentCapabilityManager.transcribe_audio(
            content=content,
            filename=file_info.get("name") or file_path.name,
        )
        if transcript:
            transcripts.append(transcript)

    return "\n".join(transcripts).strip() if transcripts else None


def _merge_web_agent_prompt_with_transcript(prompt: str, transcript: Optional[str]) -> str:
    """合并用户输入文本和语音转写文本，避免重复发送相同内容。"""
    merged_parts = []
    seen_parts = set()
    for item in (prompt, transcript or ""):
        normalized = item.strip()
        if not normalized or normalized in seen_parts:
            continue
        seen_parts.add(normalized)
        merged_parts.append(normalized)
    return "\n".join(merged_parts).strip()


def _parse_web_agent_choice_callback(callback_data: str) -> Optional[tuple[str, int]]:
    """
    解析 Web Agent 按钮选择回调数据。

    :param callback_data: Agent 按钮携带的回调数据
    :return: 请求 ID 与选项序号，格式无效时返回 None
    """
    if not callback_data.startswith("agent_interaction:choice:"):
        return None
    try:
        _, _, request_id, option_index = callback_data.split(":", 3)
    except ValueError:
        return None
    if not request_id or not option_index.isdigit():
        return None
    return request_id, int(option_index)


def _flatten_web_agent_choice_buttons(buttons: Optional[list[list[dict]]]) -> list[dict]:
    """
    将消息渠道按钮二维结构转换为 Web 前端可渲染的一维选项列表。

    :param buttons: Notification 中的按钮行
    :return: Web 选择卡片按钮列表
    """
    flattened = []
    for row in buttons or []:
        for button in row or []:
            text = str(button.get("text") or "").strip()
            callback_data = str(button.get("callback_data") or "").strip()
            if not text or not callback_data:
                continue
            flattened.append(
                {
                    "label": text,
                    "callback_data": callback_data,
                }
            )
    return flattened


def _build_web_agent_choice_event(notification: schemas.Notification) -> Optional[dict]:
    """
    将带按钮通知转换为 Web Agent 选择卡片事件。

    :param notification: Agent 工具发出的按钮通知
    :return: 选择卡片事件，按钮为空时返回 None
    """
    buttons = _flatten_web_agent_choice_buttons(notification.buttons)
    if not buttons:
        return None

    choice_id = None
    parsed = _parse_web_agent_choice_callback(buttons[0]["callback_data"])
    if parsed:
        choice_id = parsed[0]

    return {
        "type": "choice",
        "choice": {
            "id": choice_id or uuid.uuid4().hex,
            "title": notification.title,
            "prompt": notification.text or "",
            "buttons": buttons,
        },
    }


def _resolve_web_agent_choice_payload(callback_data: str, user_id: str) -> Optional[dict]:
    """
    解析并消费 Web Agent 按钮选择，生成前端反馈与下一条用户消息。

    :param callback_data: 前端点击的按钮回调数据
    :param user_id: 当前登录用户 ID
    :return: 可返回给前端的数据，选择无效时返回 None
    """
    parsed = _parse_web_agent_choice_callback(callback_data)
    if not parsed:
        return None

    request_id, option_index = parsed
    resolved = agent_interaction_manager.resolve(
        request_id=request_id,
        option_index=option_index,
        user_id=str(user_id),
    )
    if not resolved:
        return None

    request, option = resolved
    return {
        "message": option.value,
        "session_id": request.session_id,
        "feedback": {
            "request_id": request.request_id,
            "title": request.title,
            "prompt": request.prompt,
            "selected_label": option.label,
            "selected_value": option.value,
        },
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
    choice_event = _build_web_agent_choice_event(notification)
    if choice_event:
        events.append(choice_event)

    text_parts = [
        str(item).strip()
        for item in (notification.title, notification.text)
        if str(item or "").strip()
    ]
    if text_parts and not choice_event:
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
        audio_path = _prepare_web_agent_audio_attachment_path(notification.voice_path)
        attachment = _register_web_agent_file(
            str(audio_path),
            file_name=audio_path.name,
            kind="audio",
            mime_type=_get_web_agent_audio_mime_type(audio_path),
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
        if not content:
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


@router.post("/upload", summary="上传 Web 智能助手附件", response_model=schemas.Response)
async def upload_web_agent_file(
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
) -> schemas.Response:
    """
    上传 Web 智能助手对话附件。

    :param file: 浏览器选择的文件
    :param session_id: 前端会话标识
    :param current_user: 当前登录用户
    :return: Agent 可消费的附件描述
    """
    mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    safe_name = _sanitize_web_agent_upload_name(file.filename, mime_type)
    upload_dir = _get_web_agent_upload_dir(current_user, session_id)
    target_path = upload_dir / f"{uuid.uuid4().hex[:8]}_{safe_name}"
    size = await _save_web_agent_upload(file, target_path)
    attachment = _register_web_agent_file(
        str(target_path),
        file_name=safe_name,
        kind=_guess_web_agent_attachment_kind(mime_type),
        mime_type=mime_type,
    )
    if not attachment:
        target_path.unlink(missing_ok=True)
        return schemas.Response(success=False, message="附件保存失败")

    attachment.update(
        {
            "ref": attachment["url"],
            "local_path": str(target_path),
            "status": "ready",
            "size": size,
        }
    )
    return schemas.Response(success=True, data=attachment)


@router.post("/callback", summary="Web 智能助手按钮回调", response_model=schemas.Response)
async def web_agent_callback(
    payload: schemas.AgentWebChoiceRequest,
    current_user: User = Depends(get_current_active_user),
) -> schemas.Response:
    """
    接收 Web 智能助手选择卡片回调。

    :param payload: 按钮选择请求
    :param current_user: 当前登录用户
    :return: 下一条需要发送给 Agent 的用户消息与卡片反馈
    """
    result = _resolve_web_agent_choice_payload(
        callback_data=payload.callback_data,
        user_id=str(current_user.id),
    )
    if not result:
        return schemas.Response(success=False, message="该选择已失效，请重新发起选择")
    return schemas.Response(success=True, data=result)


@router.post("/stream", summary="Web智能助手流式对话")
async def web_agent_stream(
    payload: schemas.AgentWebChatRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
) -> StreamingResponse:
    """
    Web 智能助手流式对话。

    :param payload: 对话请求
    :param request: 当前 HTTP 请求
    :param current_user: 当前登录用户
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
    transcript = _transcribe_web_agent_audio_refs(payload.audio_refs or [])
    prompt = _merge_web_agent_prompt_with_transcript(prompt, transcript)
    has_audio_input = bool(transcript)
    if not prompt and payload.audio_refs and not payload.images and not payload.files:
        return StreamingResponse(
            iter([
                _build_web_agent_sse(
                    "error",
                    {"message": "语音识别失败，请稍后重试。"},
                )
            ]),
            media_type="text/event-stream",
        )
    if not prompt and not payload.images and not payload.files and not payload.audio_refs:
        return StreamingResponse(
            iter([
                _build_web_agent_sse(
                    "error",
                    {"message": "请输入要发送给智能助手的内容或选择附件。"},
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
        audio_ref_set = set(payload.audio_refs or [])
        files = [
            file.model_dump(exclude_none=True)
            for file in (payload.files or [])
            if file.ref not in audio_ref_set
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
                    has_audio_input=has_audio_input,
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
