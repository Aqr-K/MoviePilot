"""搜索网络内容工具"""

import json
import re
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.config import settings
from app.log import logger
from app.utils.http import AsyncRequestUtils


class SearchWebInput(BaseModel):
    """搜索网络内容工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    query: str = Field(..., description="The search query string to search for on the web")
    max_results: Optional[int] = Field(5, description="Maximum number of search results to return (default: 5, max: 10)")


class SearchWebTool(MoviePilotTool):
    name: str = "search_web"
    description: str = "Search the web for information when you need to find current information, facts, or references that you're uncertain about. Returns search results with titles, snippets, and URLs. Use this tool to get up-to-date information from the internet."
    args_schema: Type[BaseModel] = SearchWebInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据搜索参数生成友好的提示消息"""
        query = kwargs.get("query", "")
        max_results = kwargs.get("max_results", 5)
        return f"正在搜索网络内容: {query} (最多返回 {max_results} 条结果)"

    async def run(self, query: str, max_results: Optional[int] = 5, **kwargs) -> str:
        """
        执行网络搜索
        
        Args:
            query: 搜索查询字符串
            max_results: 最大返回结果数（默认5，最大10）
            
        Returns:
            格式化的搜索结果JSON字符串
        """
        logger.info(f"执行工具: {self.name}, 参数: query={query}, max_results={max_results}")

        try:
            # 限制最大结果数
            max_results = min(max(1, max_results or 5), 10)
            
            # 使用DuckDuckGo API进行搜索
            search_results = await self._search_duckduckgo_api(query, max_results)
            
            if not search_results:
                return f"未找到与 '{query}' 相关的搜索结果"
            
            # 裁剪结果以避免占用过多上下文
            formatted_results = self._format_and_truncate_results(search_results, max_results)
            
            result_json = json.dumps(formatted_results, ensure_ascii=False, indent=2)
            return result_json
            
        except Exception as e:
            error_message = f"搜索网络内容失败: {str(e)}"
            logger.error(f"搜索网络内容失败: {e}", exc_info=True)
            return error_message

    async def _search_duckduckgo_api(self, query: str, max_results: int) -> list:
        """
        使用DuckDuckGo API进行搜索
        
        Args:
            query: 搜索查询
            max_results: 最大结果数
            
        Returns:
            搜索结果列表
        """
        try:
            # DuckDuckGo Instant Answer API
            api_url = "https://api.duckduckgo.com/"
            params = {
                "q": query,
                "format": "json",
                "no_html": "1",
                "skip_disambig": "1"
            }
            
            # 使用代理（如果配置了）
            http_utils = AsyncRequestUtils(
                proxies=settings.PROXY,
                timeout=10
            )
            
            data = await http_utils.get_json(api_url, params=params)
            
            results = []
            
            if data:
                # 处理AbstractText（摘要）
                if data.get("AbstractText"):
                    results.append({
                        "title": data.get("Heading", query),
                        "snippet": data.get("AbstractText", ""),
                        "url": data.get("AbstractURL", ""),
                        "source": "DuckDuckGo Abstract"
                    })
                
                # 处理RelatedTopics（相关主题）
                related_topics = data.get("RelatedTopics", [])
                for topic in related_topics[:max_results - len(results)]:
                    if isinstance(topic, dict):
                        text = topic.get("Text", "")
                        first_url = topic.get("FirstURL", "")
                        if text and first_url:
                            # 提取标题（通常在" - "之前）
                            title = text.split(" - ")[0] if " - " in text else text[:100]
                            snippet = text
                            
                            results.append({
                                "title": title.strip(),
                                "snippet": snippet,
                                "url": first_url,
                                "source": "DuckDuckGo Related"
                            })
                
                # 处理Results（搜索结果）
                api_results = data.get("Results", [])
                for result in api_results[:max_results - len(results)]:
                    if isinstance(result, dict):
                        title = result.get("Text", "")
                        url = result.get("FirstURL", "")
                        if title and url:
                            results.append({
                                "title": title,
                                "snippet": result.get("Text", ""),
                                "url": url,
                                "source": "DuckDuckGo Results"
                            })
            
            return results[:max_results]
            
        except Exception as e:
            logger.warning(f"DuckDuckGo API搜索失败: {e}")
            return []

    def _format_and_truncate_results(self, results: list, max_results: int) -> dict:
        """
        格式化并裁剪搜索结果以避免占用过多上下文
        
        Args:
            results: 原始搜索结果列表
            max_results: 最大结果数
            
        Returns:
            格式化后的结果字典
        """
        formatted = {
            "total_results": len(results),
            "results": []
        }
        
        # 限制结果数量
        limited_results = results[:max_results]
        
        for idx, result in enumerate(limited_results, 1):
            title = result.get("title", "")[:200]  # 限制标题长度
            snippet = result.get("snippet", "")
            url = result.get("url", "")
            source = result.get("source", "Unknown")
            
            # 裁剪摘要，避免过长
            max_snippet_length = 300  # 每个摘要最多300字符
            if len(snippet) > max_snippet_length:
                snippet = snippet[:max_snippet_length] + "..."
            
            # 清理文本，移除多余的空白字符
            snippet = re.sub(r'\s+', ' ', snippet).strip()
            
            formatted["results"].append({
                "rank": idx,
                "title": title,
                "snippet": snippet,
                "url": url,
                "source": source
            })
        
        # 添加提示信息
        if len(results) > max_results:
            formatted["note"] = f"注意：共找到 {len(results)} 条结果，为节省上下文空间，仅显示前 {max_results} 条结果。"
        
        return formatted
