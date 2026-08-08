# -*- coding: utf-8 -*-
"""
挑战-应答短时状态存储 —— 内存 + 锁 + TTL，仿 ``app/core/auth/redirect.py`` 的 ``RedirectStateStore``。

用于"服务端先下发、用户再应答"的带外因子（SMS/Email OTP、推送等）：首次请求时由因子
``put`` 一条挑战状态（键如 ``f"{user_id}:{factor_id}"``），用户带码再次请求时 ``consume``/``get`` 校验。
保持 db-free 与无 token：挑战短时，进程内存足矣（重启失效可接受），``security.py`` 零改动。
"""
import time
from threading import RLock
from typing import Any, Callable, Dict, Optional, Tuple


class ChallengeStore:
    """按调用方提供的键存放短时挑战状态；TTL 过期自动清理。``now`` 可注入以便测试。"""

    def __init__(self, ttl_seconds: int = 600, now: Optional[Callable[[], float]] = None) -> None:
        self._ttl = ttl_seconds
        self._now = now or time.time
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}   # key -> (issued_at, payload)
        self._lock = RLock()

    def put(self, key: str, payload: Optional[Dict[str, Any]] = None) -> None:
        """写入/覆盖一条挑战状态。"""
        now = self._now()
        with self._lock:
            self._cleanup(now)
            self._store[key] = (now, dict(payload or {}))

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """读取（不消费）一条未过期挑战，返回 payload 副本；不存在/过期返回 None。"""
        now = self._now()
        with self._lock:
            self._cleanup(now)
            entry = self._store.get(key)
            return dict(entry[1]) if entry else None

    def consume(self, key: str) -> Optional[Dict[str, Any]]:
        """取用并删除一条未过期挑战（单次有效）；不存在/过期返回 None。"""
        now = self._now()
        with self._lock:
            entry = self._store.pop(key, None)
            self._cleanup(now)
        if not entry:
            return None
        issued_at, payload = entry
        if (now - issued_at) > self._ttl:
            return None
        return dict(payload)

    def delete(self, key: str) -> None:
        """主动删除一条挑战状态。"""
        with self._lock:
            self._store.pop(key, None)

    def _cleanup(self, now: float) -> None:
        expired = [k for k, (t, _) in self._store.items() if (now - t) > self._ttl]
        for k in expired:
            self._store.pop(k, None)
