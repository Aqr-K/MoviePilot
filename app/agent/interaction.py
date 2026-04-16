"""Agent 客户端交互请求管理。"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional
import uuid


@dataclass(frozen=True)
class AgentInteractionOption:
    """交互选项。"""

    label: str
    value: str


@dataclass
class PendingAgentInteraction:
    """待处理的 Agent 客户端交互请求。"""

    request_id: str
    session_id: str
    user_id: str
    channel: Optional[str]
    source: Optional[str]
    username: Optional[str]
    title: Optional[str]
    prompt: str
    options: List[AgentInteractionOption]
    created_at: datetime = field(default_factory=datetime.now)


class AgentInteractionManager:
    """管理 Agent 发起的客户端交互请求。"""

    _ttl = timedelta(hours=24)

    def __init__(self):
        self._pending_interactions: Dict[str, PendingAgentInteraction] = {}
        self._lock = Lock()

    def _cleanup_locked(self):
        expire_before = datetime.now() - self._ttl
        expired_ids = [
            request_id
            for request_id, request in self._pending_interactions.items()
            if request.created_at < expire_before
        ]
        for request_id in expired_ids:
            self._pending_interactions.pop(request_id, None)

    def create_request(
        self,
        session_id: str,
        user_id: str,
        channel: Optional[str],
        source: Optional[str],
        username: Optional[str],
        title: Optional[str],
        prompt: str,
        options: List[AgentInteractionOption],
    ) -> PendingAgentInteraction:
        with self._lock:
            self._cleanup_locked()
            request_id = uuid.uuid4().hex[:12]
            while request_id in self._pending_interactions:
                request_id = uuid.uuid4().hex[:12]
            request = PendingAgentInteraction(
                request_id=request_id,
                session_id=session_id,
                user_id=str(user_id),
                channel=channel,
                source=source,
                username=username,
                title=title,
                prompt=prompt,
                options=options,
            )
            self._pending_interactions[request_id] = request
            return request

    def resolve(
        self,
        request_id: str,
        option_index: int,
        user_id: Optional[str] = None,
    ) -> Optional[tuple[PendingAgentInteraction, AgentInteractionOption]]:
        with self._lock:
            self._cleanup_locked()
            request = self._pending_interactions.get(request_id)
            if not request:
                return None
            if user_id is not None and str(request.user_id) != str(user_id):
                return None
            if option_index < 1 or option_index > len(request.options):
                return None
            option = request.options[option_index - 1]
            self._pending_interactions.pop(request_id, None)
            return request, option

    def clear(self):
        with self._lock:
            self._pending_interactions.clear()


agent_interaction_manager = AgentInteractionManager()
