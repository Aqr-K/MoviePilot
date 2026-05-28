import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from app.agent.tools.impl.search_web import DEFAULT_SEARCH_ENGINE, SearchWebTool
from app.core.config import settings


class TestAgentSearchWebTool(unittest.TestCase):
    """Agent 网络搜索工具测试"""

    def test_build_search_query_adds_site_filter(self):
        """指定网址时应生成搜索引擎可识别的 site 查询"""
        site_filter = SearchWebTool._normalize_site_filter("https://docs.python.org/3/")

        self.assertEqual("docs.python.org", site_filter.domain)
        self.assertEqual("/3", site_filter.path)
        self.assertEqual("docs.python.org/3", site_filter.search_target)
        self.assertEqual(
            "asyncio site:docs.python.org/3",
            SearchWebTool._build_search_query("asyncio", site_filter),
        )

    def test_build_search_query_keeps_existing_site_operator(self):
        """用户已写 site 条件时不应重复追加限定条件"""
        site_filter = SearchWebTool._normalize_site_filter("python.org")

        self.assertEqual(
            "asyncio site:docs.python.org",
            SearchWebTool._build_search_query("asyncio site:docs.python.org", site_filter),
        )

    def test_filter_results_by_site_matches_domain_and_path(self):
        """站点过滤应同时约束域名和路径前缀"""
        site_filter = SearchWebTool._normalize_site_filter("https://docs.python.org/3/")
        results = [
            {"url": "https://docs.python.org/3/library/asyncio.html"},
            {"url": "https://www.docs.python.org/3/tutorial/index.html"},
            {"url": "https://docs.python.org/2/library/asyncio.html"},
            {"url": "https://example.com/3/library/asyncio.html"},
        ]

        filtered_results = SearchWebTool._filter_results_by_site(results, site_filter)

        self.assertEqual(2, len(filtered_results))
        self.assertEqual(
            "https://docs.python.org/3/library/asyncio.html",
            filtered_results[0]["url"],
        )

    def test_auto_search_plan_falls_back_to_search_engine(self):
        """没有 API Key 时自动模式应退回搜索引擎后端"""
        with patch.object(settings, "EXA_API_KEY", ""), patch.object(
            settings, "TAVILY_API_KEY", []
        ):
            search_plan = SearchWebTool._get_search_plan(DEFAULT_SEARCH_ENGINE)

        self.assertEqual([DEFAULT_SEARCH_ENGINE], search_plan)

    def test_run_uses_specific_search_engine_and_site_filter(self):
        """显式搜索引擎和指定网址应传入后端搜索调用"""

        async def _run_tool():
            """执行一次带 mock 后端的搜索工具调用"""
            tool = SearchWebTool(session_id="session-1", user_id="10001")
            with patch.object(
                tool,
                "_search_with_backend",
                new_callable=AsyncMock,
            ) as search_mock:
                search_mock.return_value = [
                    {
                        "title": "asyncio",
                        "snippet": "Python asyncio docs",
                        "url": "https://docs.python.org/3/library/asyncio.html",
                        "source": "DuckDuckGo",
                    }
                ]

                result = await tool.run(
                    query="asyncio",
                    max_results=5,
                    search_engine="duckduckgo",
                    site_url="https://docs.python.org/3/",
                )
                return result, search_mock.await_args.kwargs

        result, call_kwargs = asyncio.run(_run_tool())
        payload = json.loads(result)

        self.assertEqual("duckduckgo", call_kwargs["engine"])
        self.assertEqual("asyncio site:docs.python.org/3", call_kwargs["query"])
        self.assertEqual("docs.python.org", call_kwargs["site_filter"].domain)
        self.assertEqual(1, payload["total_results"])
        self.assertEqual("DuckDuckGo", payload["results"][0]["source"])


if __name__ == "__main__":
    unittest.main()
