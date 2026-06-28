from enum import Enum
from typing import Union, Optional

from app.core.cache import TTLCache
from app.schemas.types import ProgressKey


class ProgressHelper:
    """
    处理进度辅助类
    """

    def __init__(self, key: Union[ProgressKey, str]) -> None:
        if isinstance(key, Enum):
            key = key.value
        self._key = key
        self._progress = TTLCache(region="progress", maxsize=1024, ttl=24 * 60 * 60)

    def __reset(self) -> None:
        """
        重置进度
        """
        self._progress[self._key] = {
            "enable": False,
            "value": 0,
            "text": "请稍候...",
            "data": {}
        }

    def start(self) -> None:
        """
        开始进度
        """
        self.__reset()
        current = self._progress.get(self._key)
        if not current:
            return
        current['enable'] = True
        self._progress[self._key] = current

    def end(
            self,
            text: Optional[str] = "",
            data: Optional[dict] = None,
            value: Optional[Union[float, int]] = 100,
    ) -> None:
        """
        结束进度
        """
        current = self._progress.get(self._key)
        if not current:
            return
        if data is not None:
            if not current.get('data'):
                current['data'] = {}
            current['data'].update(data)
        current["enable"] = False
        if value is not None:
            current["value"] = max(min(float(value), 100), 0)
        current["text"] = text or ""
        self._progress[self._key] = current

    def update(
            self,
            value: Optional[Union[float, int]] = None,
            text: Optional[str] = None,
            data: Optional[dict] = None,
    ) -> None:
        """
        更新进度
        """
        current = self._progress.get(self._key)
        if not current or not current.get('enable'):
            return
        if value is not None:
            current['value'] = max(min(float(value), 100), 0)
        if text is not None:
            current['text'] = text
        if data is not None:
            if not current.get('data'):
                current['data'] = {}
            current['data'].update(data)
        self._progress[self._key] = current

    def get(self) -> Optional[dict]:
        """
        获取当前进度
        """
        return self._progress.get(self._key)
