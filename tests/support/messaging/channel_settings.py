"""
渠道配置测试使用的隔离内存事务替身。
"""

import asyncio
from copy import deepcopy

from app.schemas.types import SystemConfigKey


class _Configuration:
    """
    用内存事务替身记录读写和无凭据的事件通知。
    """

    def __init__(self, rows):
        """
        用一份旧通知配置建立迁移起点。
        """
        self.events = []
        self._lock = asyncio.Lock()
        self.state = {SystemConfigKey.Notifications: rows}

    def get(self, key):
        """
        返回配置值的独立副本。
        """
        return deepcopy(self.state.get(key))

    async def async_update_atomically(self, key, change):
        """
        只在应用回调成功完成时发布新值。
        """
        async with self._lock:
            result, value = change(self.get(key))
            self.state[key] = value
            return result

    async def async_publish_committed_change(self, key):
        """
        记录事务完成后的配置失效键。
        """
        assert key in self.state
        self.events.append(key)
