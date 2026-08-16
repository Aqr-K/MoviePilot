"""MusicBrainz 公共接口客户端。

负责与 MusicBrainz Web Service 通信的全部底层事务：复用 HTTP 会话、遵守公共接口
每秒一次的调用频率、在服务端繁忙时退避重试、缓存 JSON 响应，以及构造符合 Lucene
语法的检索表达式。识别语义（文本归一化、候选评分、响应映射）不在本模块。
"""
import asyncio
import re
import threading
import time
from typing import Any, Optional

from requests import Session

from app.adapters.network.http import AsyncRequestUtils, RequestUtils
from app.runtime.cache import cached
from app.runtime.config import settings
from app.runtime.log import logger


class MusicBrainzApi:
    """封装 MusicBrainz Web Service 的请求发送、频率控制与检索式构造。"""

    _base_url = "https://musicbrainz.org/ws/2"
    # 条目详情页地址，供响应映射拼接可跳转的外部链接
    detail_url = "https://musicbrainz.org/recording"
    album_detail_url = "https://musicbrainz.org/release-group"
    artist_detail_url = "https://musicbrainz.org/artist"
    # 封面归档的专辑封面地址前缀
    cover_url = "https://coverartarchive.org/release-group"
    # 公共接口限制每秒一次调用，请求之间至少间隔该秒数
    _request_interval = 1.0
    # 服务端繁忙（429/5xx）时的重试次数与退避基数，重试间隔随次数翻倍递增
    _busy_retries = 2
    _busy_backoff = 5.0
    # 中日韩字符：Lucene 标准分词器不会切分连续 CJK，短语检索对中文标题永远零命中
    _QUERY_CJK_RE = re.compile(
        r"[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uAC00-\uD7AF]")
    # 检索词元切分：按空白、标点与括号拆分，保留 CJK 串与拉丁词（括号对逐字检索无意义）
    _QUERY_TOKEN_SPLIT_RE = re.compile(
        r"[\s\-–—−－。，、；：！？·．…()（）「」『』【】\[\]《》,;]+")

    def __init__(self) -> None:
        """初始化会话与频率控制状态。"""
        self._session: Optional[Session] = None
        self._session_lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._last_request_at = 0.0

    def _get_session(self) -> Session:
        """懒创建并复用 HTTP 会话，批量识别时避免重复建连。

        :return: 可复用的 HTTP 会话
        """
        if self._session is None:
            with self._session_lock:
                if self._session is None:
                    self._session = Session()
        return self._session

    def close(self) -> None:
        """关闭 HTTP 会话并释放保持的连接。"""
        with self._session_lock:
            if self._session:
                self._session.close()
                self._session = None

    def _reserve_request_delay(self) -> float:
        """为同步和异步请求统一预留发送时间。

        :return: 距离预留发送时间还需等待的秒数
        """
        with self._request_lock:
            now = time.monotonic()
            request_at = max(now, self._last_request_at + self._request_interval)
            self._last_request_at = request_at
            return max(0.0, request_at - now)

    def _wait_for_rate_limit(self) -> None:
        """同步等待已预留的请求发送时间。"""
        if delay := self._reserve_request_delay():
            time.sleep(delay)

    async def _async_wait_for_rate_limit(self) -> None:
        """异步等待已预留的请求发送时间。"""
        if delay := self._reserve_request_delay():
            await asyncio.sleep(delay)

    @cached(maxsize=settings.CONF.musicbrainz, ttl=settings.CONF.meta, skip_none=True,
            shared_key="request_json")
    def request_json(
            self,
            path: str,
            params: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        """请求 MusicBrainz JSON 接口并统一处理网络和响应错误。

        服务端繁忙（429/5xx）属于瞬时错误，退避重试后再失败才放弃，
        避免批量识别场景下把限流误判为检索零命中。

        :param path: 接口路径，以 / 开头
        :param params: 查询参数
        :return: 响应 JSON；资源不存在返回空字典，请求失败返回 None
        """
        attempts = self._busy_retries + 1
        for attempt in range(attempts):
            self._wait_for_rate_limit()
            response = RequestUtils(
                headers={
                    "User-Agent": f"{settings.USER_AGENT} (https://github.com/jxxghp/MoviePilot)",
                    "Accept": "application/json",
                },
                proxies=settings.PROXY,
                session=self._get_session(),
                timeout=20,
            ).get_res(f"{self._base_url}{path}", params=params)
            if response is None:
                return None
            status_code = response.status_code
            try:
                if status_code == 404:
                    # 单曲与专辑共用同一套 ID 入口，404 属于正常的探测结果
                    logger.debug(f"MusicBrainz 资源不存在：{path}")
                    # 使用空对象区分稳定的不存在与瞬时请求失败，使有界缓存能够复用探测结果。
                    return {}
                if status_code == 429 or status_code >= 500:
                    logger.warning(
                        f"MusicBrainz 服务繁忙：{status_code} {response.text[:200]}"
                    )
                    if attempt < attempts - 1:
                        time.sleep(self._busy_backoff * (2 ** attempt))
                        continue
                    return None
                if status_code != 200:
                    logger.warning(
                        f"MusicBrainz 请求失败：{status_code} {response.text[:200]}"
                    )
                    return None
                return response.json()
            except (TypeError, ValueError) as err:
                logger.warning(f"MusicBrainz 响应解析失败：{err}")
                return None
            finally:
                response.close()
        return None

    @cached(
        maxsize=settings.CONF.musicbrainz,
        ttl=settings.CONF.meta,
        skip_none=True,
        shared_key="request_json",
    )
    async def async_request_json(
            self,
            path: str,
            params: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        """异步请求 MusicBrainz JSON 接口并统一处理限流与响应错误。

        :param path: 接口路径，以 / 开头
        :param params: 查询参数
        :return: 响应 JSON；资源不存在返回空字典，请求失败返回 None
        """
        attempts = self._busy_retries + 1
        for attempt in range(attempts):
            await self._async_wait_for_rate_limit()
            response = await AsyncRequestUtils(
                headers={
                    "User-Agent": f"{settings.USER_AGENT} (https://github.com/jxxghp/MoviePilot)",
                    "Accept": "application/json",
                },
                proxies=settings.PROXY,
                timeout=20,
            ).get_res(f"{self._base_url}{path}", params=params)
            if response is None:
                return None
            status_code = response.status_code
            try:
                if status_code == 404:
                    logger.debug(f"MusicBrainz 资源不存在：{path}")
                    return {}
                if status_code == 429 or status_code >= 500:
                    logger.warning(
                        f"MusicBrainz 服务繁忙：{status_code} {response.text[:200]}"
                    )
                    if attempt < attempts - 1:
                        await asyncio.sleep(self._busy_backoff * (2 ** attempt))
                        continue
                    return None
                if status_code != 200:
                    logger.warning(
                        f"MusicBrainz 请求失败：{status_code} {response.text[:200]}"
                    )
                    return None
                payload = response.json()
                return payload if isinstance(payload, dict) else None
            except (TypeError, ValueError) as err:
                logger.warning(f"MusicBrainz 响应解析失败：{err}")
                return None
            finally:
                await response.aclose()
        return None

    @staticmethod
    def escape_query(value: str) -> str:
        """转义 MusicBrainz 查询中的引号和反斜线。

        :param value: 待转义的检索词
        :return: 可安全嵌入检索式的文本
        """
        return value.replace("\\", "\\\\").replace('"', '\\"').strip()

    @classmethod
    def query_phrase(cls, value: Optional[str]) -> Optional[str]:
        """构造适配 Lucene 分词的检索表达式。

        无 CJK 的普通文本返回带引号短语；含 CJK 的文本拆为词元后用 OR 交集检索，
        MusicBrainz 索引中连续 CJK 是单一词元，逐字 OR 才能命中（「茹此精彩十三首」）；
        过宽的召回由候选挑选阶段的标题与艺术家比对收紧。

        :param value: 检索词原文
        :return: 检索表达式；文本为空时返回 None
        """
        text = str(value or "").strip()
        if not text:
            return None
        if not cls._QUERY_CJK_RE.search(text):
            return f'"{cls.escape_query(text)}"'
        tokens = [
            token for token in cls._QUERY_TOKEN_SPLIT_RE.split(text) if token.strip()
        ]
        if not tokens:
            return None
        parts = [
            f'"{cls.escape_query(token)}"'
            if not cls._QUERY_CJK_RE.search(token) else cls.or_group(
                [f'"{cls.escape_query(char)}"' for char in token]
            )
            for token in tokens
        ]
        return cls.or_group(parts)

    @staticmethod
    def or_group(parts: list[str]) -> str:
        """拼接 OR 检索表达式，多项时用括号包裹避免与外层 AND 产生优先级歧义。

        :param parts: 参与 OR 的检索表达式列表
        :return: 拼接后的检索表达式
        """
        if len(parts) == 1:
            return parts[0]
        return "(" + " OR ".join(parts) + ")"
