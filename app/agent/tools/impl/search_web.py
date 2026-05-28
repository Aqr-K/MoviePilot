import asyncio
import json
import random
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Type
from urllib.parse import urlparse

from ddgs import DDGS
from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.config import settings
from app.log import logger
from app.utils.http import AsyncRequestUtils

# 搜索超时时间（秒）
SEARCH_TIMEOUT = 20
# 单次搜索最多返回结果数
MAX_SEARCH_RESULTS = 20
# 默认搜索源
DEFAULT_SEARCH_ENGINE = "auto"
# 可显式调用的搜索引擎后端
SEARCH_ENGINE_BACKENDS = (
    "auto",
    "duckduckgo",
    "google",
    "bing",
    "brave",
    "yahoo",
    "wikipedia",
    "yandex",
    "mojeek",
)
# 可显式调用的搜索 API 后端
SEARCH_API_BACKENDS = ("exa", "tavily")
SUPPORTED_SEARCH_ENGINES = SEARCH_API_BACKENDS + SEARCH_ENGINE_BACKENDS
SITE_SEARCH_PATTERN = re.compile(r"\bsite:", re.IGNORECASE)


@dataclass(frozen=True)
class _SearchSiteFilter:
    """站点限定搜索参数"""

    domain: str
    path: str
    search_target: str


class SearchWebInput(BaseModel):
    """搜索网络内容工具的输入参数模型"""

    explanation: Optional[str] = Field(
        None,
        description="Clear explanation of why this tool is being used in the current context",
    )
    query: str = Field(
        ..., description="The search query string to search for on the web"
    )
    max_results: Optional[int] = Field(
        MAX_SEARCH_RESULTS,
        description="Maximum number of search results to return (default: 20, max: 20)",
    )
    search_engine: Optional[str] = Field(
        DEFAULT_SEARCH_ENGINE,
        description=(
            "Search backend to use. Supported values: auto, exa, tavily, "
            "duckduckgo, google, bing, brave, yahoo, wikipedia, yandex, mojeek. "
            "Use auto unless the user asks for a specific search engine."
        ),
    )
    site_url: Optional[str] = Field(
        None,
        description=(
            "Optional website/domain/URL to limit the search to, for example "
            "'https://docs.python.org/3/' or 'github.com'."
        ),
    )


class SearchWebTool(MoviePilotTool):
    """
    网络搜索工具，支持 API 搜索、搜索引擎搜索和指定站点限定搜索。
    """

    name: str = "search_web"
    description: str = (
        "Search the web for information when you need current information, facts, "
        "or references. Supports automatic API-backed search, explicit search "
        "engine selection, and site_url-limited searches for a specified website "
        "or URL. Returns search results with titles, snippets, and URLs."
    )
    args_schema: Type[BaseModel] = SearchWebInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据搜索参数生成友好的提示消息"""
        query = kwargs.get("query", "")
        max_results = kwargs.get("max_results", MAX_SEARCH_RESULTS)
        search_engine = self._normalize_search_engine(kwargs.get("search_engine"))
        site_url = kwargs.get("site_url")
        message = f"搜索网络内容: {query} (最多返回 {max_results} 条结果"
        if search_engine != DEFAULT_SEARCH_ENGINE:
            message += f"，搜索源: {search_engine}"
        if site_url:
            message += f"，限定站点: {site_url}"
        return f"{message})"

    async def run(
        self,
        query: str,
        max_results: Optional[int] = MAX_SEARCH_RESULTS,
        search_engine: Optional[str] = DEFAULT_SEARCH_ENGINE,
        site_url: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        执行网络搜索。

        :param query: 搜索关键词
        :param max_results: 最大返回结果数
        :param search_engine: 指定搜索源，默认自动选择
        :param site_url: 指定站点或网址，传入时只返回该范围内的搜索结果
        :return: JSON格式的搜索结果或错误信息
        """
        search_engine = self._normalize_search_engine(search_engine)
        if search_engine not in SUPPORTED_SEARCH_ENGINES:
            supported = ", ".join(SUPPORTED_SEARCH_ENGINES)
            return f"错误: 不支持的搜索源 '{search_engine}'，支持的搜索源: {supported}"

        site_filter = self._normalize_site_filter(site_url)
        if site_url and not site_filter:
            return f"错误: site_url 无效，无法限定搜索范围: {site_url}"

        search_query = self._build_search_query(query=query, site_filter=site_filter)
        if not search_query:
            return "错误: query 不能为空"

        logger.info(
            f"执行工具: {self.name}, 参数: query={query}, "
            f"max_results={max_results}, search_engine={search_engine}, site_url={site_url}"
        )

        try:
            # 限制最大结果数
            max_results = min(
                max(1, max_results or MAX_SEARCH_RESULTS),
                MAX_SEARCH_RESULTS,
            )
            results: List[Dict] = []

            for engine in self._get_search_plan(search_engine):
                results = await self._search_with_backend(
                    engine=engine,
                    query=search_query,
                    max_results=max_results,
                    site_filter=site_filter,
                )
                if results:
                    break

            if not results:
                return f"未找到与 '{search_query}' 相关的搜索结果"

            # 格式化并裁剪结果
            formatted_results = self._format_and_truncate_results(results, max_results)
            return json.dumps(formatted_results, ensure_ascii=False, indent=2)

        except Exception as e:
            error_message = f"搜索网络内容失败: {str(e)}"
            logger.error(f"搜索网络内容失败: {e}", exc_info=True)
            return error_message

    @staticmethod
    def _normalize_search_engine(search_engine: Optional[str]) -> str:
        """规范化搜索源参数"""
        engine = (search_engine or DEFAULT_SEARCH_ENGINE).strip().lower()
        aliases = {
            "ddg": "duckduckgo",
            "duck": "duckduckgo",
            "search": DEFAULT_SEARCH_ENGINE,
            "search_engine": DEFAULT_SEARCH_ENGINE,
        }
        return aliases.get(engine, engine)

    @staticmethod
    def _get_search_plan(search_engine: str) -> List[str]:
        """根据搜索源配置生成兜底搜索顺序"""
        if search_engine != DEFAULT_SEARCH_ENGINE:
            return [search_engine]

        search_plan: List[str] = []
        if settings.EXA_API_KEY:
            search_plan.append("exa")
        if SearchWebTool._choose_tavily_api_key():
            search_plan.append("tavily")
        search_plan.append(DEFAULT_SEARCH_ENGINE)
        return search_plan

    async def _search_with_backend(
        self,
        engine: str,
        query: str,
        max_results: int,
        site_filter: Optional[_SearchSiteFilter],
    ) -> List[Dict]:
        """
        使用指定后端执行搜索。

        :param engine: 搜索后端名称
        :param query: 已加工的搜索关键词
        :param max_results: 最大结果数
        :param site_filter: 站点限定条件
        :return: 搜索结果列表
        """
        if engine == "exa":
            logger.info("使用 Exa 进行搜索...")
            return await self._search_exa(query, max_results, site_filter)
        if engine == "tavily":
            logger.info("使用 Tavily 进行搜索...")
            return await self._search_tavily(query, max_results, site_filter)

        logger.info(f"使用搜索引擎 {engine} 进行搜索...")
        return await self._search_duckduckgo(query, max_results, engine, site_filter)

    @staticmethod
    async def _search_tavily(
        query: str,
        max_results: int,
        site_filter: Optional[_SearchSiteFilter] = None,
    ) -> List[Dict]:
        """使用 Tavily API 进行搜索"""
        response = None
        try:
            # 从设置中随机选择一个 API Key（如果有多个）
            tavily_api_key = SearchWebTool._choose_tavily_api_key()
            if not tavily_api_key:
                return []
            payload = {
                "api_key": tavily_api_key,
                "query": query,
                "search_depth": "basic",
                "max_results": max_results,
                "include_answer": False,
                "include_images": False,
                "include_raw_content": False,
            }
            if site_filter:
                payload["include_domains"] = [site_filter.domain]

            response = await AsyncRequestUtils(
                ua=settings.USER_AGENT,
                proxies=settings.PROXY,
                timeout=SEARCH_TIMEOUT,
                content_type="application/json",
                accept_type="application/json",
            ).post_res(
                "https://api.tavily.com/search",
                json=payload,
            )
            if not response or response.status_code != 200:
                status_code = response.status_code if response else "无响应"
                logger.warning(f"Tavily 搜索失败，HTTP状态码: {status_code}")
                return []
            data = response.json()

            results = []
            for result in data.get("results", []):
                results.append(
                    {
                        "title": result.get("title", ""),
                        "snippet": result.get("content", ""),
                        "url": result.get("url", ""),
                        "source": "Tavily",
                    }
                )
            return SearchWebTool._filter_results_by_site(results, site_filter)
        except Exception as e:
            logger.warning(f"Tavily 搜索失败: {e}")
            return []
        finally:
            if response is not None:
                await response.aclose()

    @staticmethod
    def _choose_tavily_api_key() -> Optional[str]:
        """从配置中选择一个可用的 Tavily API Key"""
        api_keys = settings.TAVILY_API_KEY
        if not api_keys:
            return None
        if isinstance(api_keys, str):
            api_keys = [api_keys]
        available_api_keys = [api_key for api_key in api_keys if api_key]
        if not available_api_keys:
            return None
        return random.choice(available_api_keys)

    @staticmethod
    async def _search_exa(
        query: str,
        max_results: int,
        site_filter: Optional[_SearchSiteFilter] = None,
    ) -> List[Dict]:
        """使用 Exa API 进行搜索"""
        response = None
        try:
            if not settings.EXA_API_KEY:
                return []
            payload = {
                "query": query,
                "numResults": max_results,
                "type": "auto",
                "contents": {"highlights": {"maxCharacters": 2000}},
            }
            if site_filter:
                payload["includeDomains"] = [site_filter.domain]

            response = await AsyncRequestUtils(
                headers={
                    "x-api-key": settings.EXA_API_KEY,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": settings.USER_AGENT,
                },
                proxies=settings.PROXY,
                timeout=SEARCH_TIMEOUT,
            ).post_res(
                "https://api.exa.ai/search",
                json=payload,
            )
            if not response or response.status_code != 200:
                status_code = response.status_code if response else "无响应"
                logger.warning(f"Exa 搜索失败，HTTP状态码: {status_code}")
                return []
            data = response.json()

            results = []
            for result in data.get("results", []):
                highlights = result.get("highlights", [])
                snippet = (
                    highlights[0] if highlights else result.get("text", "")[:500]
                )
                results.append(
                    {
                        "title": result.get("title", ""),
                        "snippet": snippet,
                        "url": result.get("url", ""),
                        "source": "Exa",
                    }
                )
            return SearchWebTool._filter_results_by_site(results, site_filter)
        except Exception as e:
            logger.warning(f"Exa 搜索失败: {e}")
            return []
        finally:
            if response is not None:
                await response.aclose()

    @staticmethod
    def _normalize_site_filter(site_url: Optional[str]) -> Optional[_SearchSiteFilter]:
        """
        将用户传入的网址转换为搜索引擎 site 过滤条件。

        :param site_url: 用户传入的站点、域名或完整URL
        :return: 站点过滤条件，无法解析时返回 None
        """
        if not site_url:
            return None

        raw_site_url = site_url.strip()
        if not raw_site_url:
            return None

        parse_target = raw_site_url
        if not re.match(r"^https?://", raw_site_url, re.IGNORECASE):
            parse_target = f"https://{raw_site_url}"

        parsed = urlparse(parse_target)
        domain = (parsed.hostname or "").lower()
        if not domain:
            return None

        path = re.sub(r"/+", "/", parsed.path or "").rstrip("/")
        search_target = f"{domain}{path}" if path else domain
        return _SearchSiteFilter(domain=domain, path=path, search_target=search_target)

    @staticmethod
    def _build_search_query(
        query: str,
        site_filter: Optional[_SearchSiteFilter],
    ) -> str:
        """
        生成实际发送给搜索后端的搜索关键词。

        :param query: 原始搜索关键词
        :param site_filter: 站点限定条件
        :return: 加入 site 过滤后的关键词
        """
        search_query = (query or "").strip()
        if not site_filter or SITE_SEARCH_PATTERN.search(search_query):
            return search_query
        if not search_query:
            return f"site:{site_filter.search_target}"
        return f"{search_query} site:{site_filter.search_target}"

    @staticmethod
    def _filter_results_by_site(
        results: List[Dict],
        site_filter: Optional[_SearchSiteFilter],
    ) -> List[Dict]:
        """
        根据指定站点过滤搜索结果。

        :param results: 原始搜索结果
        :param site_filter: 站点限定条件
        :return: 站点范围内的搜索结果
        """
        if not site_filter:
            return results
        return [
            result
            for result in results
            if SearchWebTool._result_matches_site(result.get("url", ""), site_filter)
        ]

    @staticmethod
    def _result_matches_site(url: str, site_filter: _SearchSiteFilter) -> bool:
        """
        判断搜索结果 URL 是否属于指定站点。

        :param url: 搜索结果 URL
        :param site_filter: 站点限定条件
        :return: URL 属于指定站点时返回 True
        """
        if not url:
            return False

        parse_target = url
        if not re.match(r"^https?://", url, re.IGNORECASE):
            parse_target = f"https://{url}"

        parsed = urlparse(parse_target)
        result_host = SearchWebTool._normalize_host(parsed.hostname or "")
        target_host = SearchWebTool._normalize_host(site_filter.domain)
        if not result_host or not target_host:
            return False
        if result_host != target_host and not result_host.endswith(f".{target_host}"):
            return False
        if not site_filter.path:
            return True

        result_path = re.sub(r"/+", "/", parsed.path or "").rstrip("/")
        return result_path == site_filter.path or result_path.startswith(
            f"{site_filter.path}/"
        )

    @staticmethod
    def _normalize_host(host: str) -> str:
        """
        标准化域名以便比较。

        :param host: 原始域名
        :return: 去掉常见 www 前缀后的域名
        """
        normalized_host = (host or "").lower()
        if normalized_host.startswith("www."):
            return normalized_host[4:]
        return normalized_host

    @staticmethod
    def _source_label(search_engine: str) -> str:
        """
        将搜索源标识转换为结果中的展示名称。

        :param search_engine: 搜索源标识
        :return: 展示名称
        """
        labels = {
            "auto": "SearchEngine",
            "duckduckgo": "DuckDuckGo",
            "google": "Google",
            "bing": "Bing",
            "brave": "Brave",
            "yahoo": "Yahoo",
            "wikipedia": "Wikipedia",
            "yandex": "Yandex",
            "mojeek": "Mojeek",
        }
        return labels.get(
            search_engine or DEFAULT_SEARCH_ENGINE,
            search_engine or "SearchEngine",
        )

    @staticmethod
    def _extract_result_url(result: Dict) -> str:
        """
        从不同搜索引擎结果结构中提取 URL。

        :param result: 搜索引擎返回的单条结果
        :return: URL 字符串
        """
        return result.get("href") or result.get("url") or ""

    @staticmethod
    def _extract_result_snippet(result: Dict) -> str:
        """
        从不同搜索引擎结果结构中提取摘要。

        :param result: 搜索引擎返回的单条结果
        :return: 摘要字符串
        """
        return (
            result.get("body")
            or result.get("snippet")
            or result.get("content")
            or ""
        )

    @staticmethod
    def _get_proxy_url(proxy_setting) -> Optional[str]:
        """从代理设置中提取代理URL"""
        if not proxy_setting:
            return None
        if isinstance(proxy_setting, dict):
            return proxy_setting.get("http") or proxy_setting.get("https")
        return proxy_setting

    async def _search_duckduckgo(
        self,
        query: str,
        max_results: int,
        search_engine: str = DEFAULT_SEARCH_ENGINE,
        site_filter: Optional[_SearchSiteFilter] = None,
    ) -> List[Dict]:
        """
        使用搜索引擎后端进行搜索。

        :param query: 搜索关键词
        :param max_results: 最大结果数
        :param search_engine: DDGS搜索后端
        :param site_filter: 站点限定条件
        :return: 搜索结果列表
        """
        try:

            def sync_search():
                """在线程中执行同步搜索"""
                results = []
                ddgs_kwargs = {"timeout": SEARCH_TIMEOUT}
                proxy_url = self._get_proxy_url(settings.PROXY)
                if proxy_url:
                    ddgs_kwargs["proxy"] = proxy_url

                try:
                    with DDGS(**ddgs_kwargs) as ddgs:
                        ddgs_results = ddgs.text(
                            query,
                            max_results=max_results,
                            backend=search_engine,
                        )
                        if ddgs_results:
                            for result in ddgs_results:
                                source = (
                                    result.get("provider")
                                    if search_engine == DEFAULT_SEARCH_ENGINE
                                    else search_engine
                                )
                                results.append(
                                    {
                                        "title": result.get("title", ""),
                                        "snippet": self._extract_result_snippet(result),
                                        "url": self._extract_result_url(result),
                                        "source": self._source_label(source),
                                    }
                                )
                except Exception as err:
                    logger.warning(f"搜索引擎搜索进程失败: {err}")
                return results

            loop = asyncio.get_running_loop()
            results = await loop.run_in_executor(None, sync_search)
            return self._filter_results_by_site(results, site_filter)

        except Exception as e:
            logger.warning(f"搜索引擎搜索失败: {e}")
            return []

    @staticmethod
    def _format_and_truncate_results(results: List[Dict], max_results: int) -> Dict:
        """格式化并裁剪搜索结果"""
        formatted = {"total_results": len(results), "results": []}

        for idx, result in enumerate(results[:max_results], 1):
            title = result.get("title", "")[:200]
            snippet = result.get("snippet", "")
            url = result.get("url", "")
            source = result.get("source", "Unknown")

            # 裁剪摘要
            max_snippet_length = 1000  # 增加到1000字符，提供更多上下文
            if len(snippet) > max_snippet_length:
                snippet = snippet[:max_snippet_length] + "..."

            # 清理文本
            snippet = re.sub(r"\s+", " ", snippet).strip()

            formatted["results"].append(
                {
                    "rank": idx,
                    "title": title,
                    "snippet": snippet,
                    "url": url,
                    "source": source,
                }
            )

        if len(results) > max_results:
            formatted["note"] = f"仅显示前 {max_results} 条结果。"

        return formatted
