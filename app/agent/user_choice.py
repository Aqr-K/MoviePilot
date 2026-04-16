"""Agent 用户按钮选择请求管理。"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional
import uuid


@dataclass(frozen=True)
class AgentChoiceOption:
    """按钮选项。"""

    label: str
    value: str


@dataclass
class PendingAgentChoice:
    """待处理的按钮选择请求。"""

    request_id: str
    session_id: str
    user_id: str
    channel: Optional[str]
    source: Optional[str]
    username: Optional[str]
    prompt: str
    options: List[AgentChoiceOption]
    created_at: datetime = field(default_factory=datetime.now)


class AgentUserChoiceManager:
    """管理 Agent 发起的按钮选择请求。"""

    _ttl = timedelta(hours=24)

    def __init__(self):
        self._pending_choices: Dict[str, PendingAgentChoice] = {}
        self._lock = Lock()

    def _cleanup_locked(self):
        expire_before = datetime.now() - self._ttl
        expired_ids = [
            request_id
            for request_id, request in self._pending_choices.items()
            if request.created_at < expire_before
        ]
        for request_id in expired_ids:
            self._pending_choices.pop(request_id, None)

    def create_request(
        self,
        session_id: str,
        user_id: str,
        channel: Optional[str],
        source: Optional[str],
        username: Optional[str],
        prompt: str,
        options: List[AgentChoiceOption],
    ) -> PendingAgentChoice:
        with self._lock:
            self._cleanup_locked()
            request_id = uuid.uuid4().hex[:12]
            while request_id in self._pending_choices:
                request_id = uuid.uuid4().hex[:12]
            request = PendingAgentChoice(
                request_id=request_id,
                session_id=session_id,
                user_id=str(user_id),
                channel=channel,
                source=source,
                username=username,
                prompt=prompt,
                options=options,
            )
            self._pending_choices[request_id] = request
            return request

    def resolve(
        self,
        request_id: str,
        option_index: int,
        user_id: Optional[str] = None,
    ) -> Optional[tuple[PendingAgentChoice, AgentChoiceOption]]:
        with self._lock:
            self._cleanup_locked()
            request = self._pending_choices.get(request_id)
            if not request:
                return None
            if user_id is not None and str(request.user_id) != str(user_id):
                return None
            if option_index < 1 or option_index > len(request.options):
                return None
            option = request.options[option_index - 1]
            self._pending_choices.pop(request_id, None)
            return request, option

    def clear(self):
        with self._lock:
            self._pending_choices.clear()


agent_user_choice_manager = AgentUserChoiceManager()
