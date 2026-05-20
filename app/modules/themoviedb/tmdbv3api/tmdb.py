# -*- coding: utf-8 -*-

import asyncio
import logging
import time
from copy import deepcopy
from datetime import datetime

import requests
import requests.exceptions

from app.core.cache import cached, fresh, async_fresh
from app.core.config import settings
from app.utils.http import RequestUtils, AsyncRequestUtils
from .exceptions import TMDbException

logger = logging.getLogger(__name__)


class TMDb(object):
    _RESPONSE_SNAPSHOT_MARKER = "__mp_tmdb_response_snapshot__"

    def __init__(self, session=None, language=None):
        self._api_key = settings.TMDB_API_KEY
        self._language = language or settings.TMDB_LOCALE or "en-US"
        self._session_id = None
        self._session = session
        self._wait_on_rate_limit = True
        self._proxies = settings.PROXY
        self._domain = settings.TMDB_API_DOMAIN
        self._page = None
        self._total_results = None
        self._total_pages = None

        if not self._session:
            self._session = requests.Session()
        self._req = RequestUtils(ua=settings.NORMAL_USER_AGENT, session=self._session, proxies=self.proxies)

        self._async_req = AsyncRequestUtils(ua=settings.NORMAL_USER_AGENT, proxies=self.proxies)

        self._remaining = 40
        self._reset = None
        self._timeout = 15

    @property
    def page(self):
        return self._page

    @property
    def total_results(self):
        return self._total_results

    @property
    def total_pages(self):
        return self._total_pages

    @property
    def api_key(self):
        return self._api_key

    @property
    def domain(self):
        return self._domain

    @property
    def proxies(self):
        return self._proxies

    @proxies.setter
    def proxies(self, proxies):
        self._proxies = proxies

    @api_key.setter
    def api_key(self, api_key):
        self._api_key = str(api_key)

    @domain.setter
    def domain(self, domain):
        self._domain = str(domain)

    @property
    def language(self):
        return self._language

    @language.setter
    def language(self, language):
        self._language = language

    @property
    def has_session(self):
        return True if self._session_id else False

    @property
    def session_id(self):
        if not self._session_id:
            raise TMDbException("Must Authenticate to create a session run Authentication(username, password)")
        return self._session_id

    @session_id.setter
    def session_id(self, session_id):
        self._session_id = session_id

    @property
    def wait_on_rate_limit(self):
        return self._wait_on_rate_limit

    @wait_on_rate_limit.setter
    def wait_on_rate_limit(self, wait_on_rate_limit):
        self._wait_on_rate_limit = bool(wait_on_rate_limit)

    @cached(maxsize=settings.CONF.tmdb, ttl=settings.CONF.meta, skip_none=True)
    def request(self, method, url, data, json, **kwargs):
        if method == "GET":
            req = self._req.get_res(url, params=data, json=json)
        else:
            req = self._req.post_res(url, data=data, json=json)
        if req is None:
            raise TMDbException("无法连接TheMovieDb，请检查网络连接！")
        return self._snapshot_response(req)

    @cached(maxsize=settings.CONF.tmdb, ttl=settings.CONF.meta, skip_none=True)
    async def async_request(self, method, url, data, json, **kwargs):
        if method == "GET":
            req = await self._async_req.get_res(url, params=data, json=json)
        else:
            req = await self._async_req.post_res(url, data=data, json=json)
        if req is None:
            raise TMDbException("无法连接TheMovieDb，请检查网络连接！")
        return self._snapshot_response(req)

    @classmethod
    def _snapshot_response(cls, response):
        """
        生成可缓存的响应快照，并在入缓存前拦截明显异常的TMDB响应结构。
        """
        json_data = cls._decode_response_json(response)
        cls._validate_json_response(json_data)
        # Redis 不能稳定序列化 requests/httpx 响应对象，缓存里只保留当前流程会用到的数据。
        return {
            cls._RESPONSE_SNAPSHOT_MARKER: True,
            "headers": dict(response.headers.items()),
            "json": json_data,
        }

    @classmethod
    def _get_response_headers(cls, response):
        if isinstance(response, dict) and response.get(cls._RESPONSE_SNAPSHOT_MARKER):
            return response.get("headers") or {}
        return response.headers

    @classmethod
    def _get_response_json(cls, response):
        if isinstance(response, dict) and response.get(cls._RESPONSE_SNAPSHOT_MARKER):
            # 调用方会补充 media_type 等字段，缓存快照必须隔离这些原地修改。
            return deepcopy(response.get("json"))
        return cls._decode_response_json(response)

    @classmethod
    def _decode_response_json(cls, response):
        """
        解析TMDB响应JSON，并把空响应、代理错误页或错误编码的响应统一转换为TMDB异常。
        """
        try:
            return response.json()
        except (ValueError, UnicodeDecodeError) as err:
            # httpx.Response.json() 在响应体是压缩字节或错误编码时会直接抛 UnicodeDecodeError，
            # 这里统一收敛成 TMDbException，避免上层把脏响应当作未捕获异常。
            raise TMDbException(cls._build_invalid_json_message(response)) from err

    @staticmethod
    def _build_invalid_json_message(response):
        """
        生成非JSON响应的诊断信息，避免日志只保留JSONDecodeError文本。
        """
        status_code = getattr(response, "status_code", None)
        headers = getattr(response, "headers", {}) or {}
        try:
            content_type = headers.get("content-type") or headers.get("Content-Type")
        except AttributeError:
            content_type = None

        try:
            response_text = getattr(response, "text", "") or ""
        except Exception as err:  # pragma: no cover - 防御异常响应对象
            response_text = f"<读取响应内容失败：{err!r}>"
        if not isinstance(response_text, str):
            response_text = repr(response_text)
        response_text = response_text.strip()
        if len(response_text) > 200:
            response_text = f"{response_text[:200]}..."

        message_parts = ["TheMovieDb 返回数据不是有效JSON"]
        if status_code is not None:
            message_parts.append(f"HTTP状态码：{status_code}")
        if content_type:
            message_parts.append(f"Content-Type：{content_type}")
        content_encoding = headers.get("content-encoding") or headers.get("Content-Encoding")
        if content_encoding:
            message_parts.append(f"Content-Encoding：{content_encoding}")
        if response_text:
            message_parts.append(f"响应内容：{response_text!r}")
        else:
            message_parts.append("响应内容为空")
        return "，".join(message_parts)

    @staticmethod
    def _validate_json_response(json_data):
        """
        校验TMDB响应JSON顶层结构，避免代理错误页等标量值继续按字典解析。
        """
        if isinstance(json_data, (dict, list)):
            return

        payload_preview = repr(json_data)
        if len(payload_preview) > 200:
            payload_preview = f"{payload_preview[:200]}..."
        raise TMDbException(
            "TheMovieDb 返回数据格式异常：期望JSON对象或数组，"
            f"实际为{type(json_data).__name__}，内容：{payload_preview}"
        )

    @staticmethod
    def _get_json_key(json_data, key):
        """
        从TMDB对象响应中读取指定字段，避免异常顶层结构触发AttributeError。
        """
        if not isinstance(json_data, dict):
            raise TMDbException(
                "TheMovieDb 返回数据格式异常："
                f"期望JSON对象包含字段 {key!r}，实际为{type(json_data).__name__}"
            )
        return json_data.get(key)

    def cache_clear(self):
        return self.request.cache_clear()

    def _validate_api_key(self):
        if self.api_key is None or self.api_key == "":
            raise TMDbException("TheMovieDb API Key 未设置！")

    def _build_url(self, action, params=""):
        return "https://%s/3%s?api_key=%s&%s&language=%s" % (
            self.domain,
            action,
            self.api_key,
            params,
            self.language,
        )

    def _handle_headers(self, headers):
        normalized_headers = {
            str(key).lower(): value for key, value in dict(headers or {}).items()
        }

        if "x-ratelimit-remaining" in normalized_headers:
            self._remaining = int(normalized_headers["x-ratelimit-remaining"])

        if "x-ratelimit-reset" in normalized_headers:
            self._reset = int(normalized_headers["x-ratelimit-reset"])

    def _handle_rate_limit(self):
        if self._remaining < 1:
            current_time = int(time.time())
            sleep_time = self._reset - current_time

            if self.wait_on_rate_limit:
                logger.warning("达到请求频率限制，休眠：%d 秒..." % sleep_time)
                return abs(sleep_time)
            else:
                raise TMDbException("达到请求频率限制，请稍后再试！")
        return 0

    def _process_json_response(self, json_data, is_async=False):
        """
        从TMDB对象响应中记录分页信息；数组响应没有分页字段，直接跳过。
        """
        if not isinstance(json_data, dict):
            return

        if "page" in json_data:
            self._page = json_data["page"]

        if "total_results" in json_data:
            self._total_results = json_data["total_results"]

        if "total_pages" in json_data:
            self._total_pages = json_data["total_pages"]

    @staticmethod
    def _handle_errors(json_data):
        """
        将TMDB标准错误字段转换为统一异常，非对象响应由结构校验提前处理。
        """
        if not isinstance(json_data, dict):
            return

        if "errors" in json_data:
            raise TMDbException(json_data["errors"])

        if "success" in json_data and json_data["success"] is False:
            raise TMDbException(json_data["status_message"])

    def _request_obj(self, action, params="", call_cached=True,
                     method="GET", data=None, json=None, key=None):
        self._validate_api_key()
        url = self._build_url(action, params)

        with fresh(not call_cached or method == "POST"):
            req = self.request(method, url, data, json,
                                      _ts=datetime.strftime(datetime.now(), '%Y%m%d'))

        if req is None:
            return None

        self._handle_headers(self._get_response_headers(req))

        rate_limit_result = self._handle_rate_limit()
        if rate_limit_result:
            logger.warning("达到请求频率限制，将在 %d 秒后重试..." % rate_limit_result)
            time.sleep(rate_limit_result)
            return self._request_obj(action, params, False, method, data, json, key)

        json_data = self._get_response_json(req)
        self._validate_json_response(json_data)
        self._process_json_response(json_data, is_async=False)
        self._handle_errors(json_data)

        if key:
            return self._get_json_key(json_data, key)
        return json_data

    async def _async_request_obj(self, action, params="", call_cached=True,
                                 method="GET", data=None, json=None, key=None):
        self._validate_api_key()
        url = self._build_url(action, params)

        async with async_fresh(not call_cached or method == "POST"):
            req = await self.async_request(method, url, data, json,
                                           _ts=datetime.strftime(datetime.now(), '%Y%m%d'))

        if req is None:
            return None

        self._handle_headers(self._get_response_headers(req))

        rate_limit_result = self._handle_rate_limit()
        if rate_limit_result:
            logger.warning("达到请求频率限制，将在 %d 秒后重试..." % rate_limit_result)
            await asyncio.sleep(rate_limit_result)
            return await self._async_request_obj(action, params, False, method, data, json, key)

        json_data = self._get_response_json(req)
        self._validate_json_response(json_data)
        self._process_json_response(json_data, is_async=True)
        self._handle_errors(json_data)

        if key:
            return self._get_json_key(json_data, key)
        return json_data

    def close(self):
        if self._session:
            self._session.close()
