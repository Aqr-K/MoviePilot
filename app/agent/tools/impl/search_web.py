"""搜索网络内容工具"""

import json
import re
from typing import Optional, Type
from urllib.parse import quote, urlparse, parse_qs

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
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
            
            # 使用DuckDuckGo搜索API
            search_results = await self._search_duckduckgo(query, max_results)
            
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

    async def _search_duckduckgo(self, query: str, max_results: int) -> list:
        """
        使用DuckDuckGo搜索API进行搜索
        
        Args:
            query: 搜索查询
            max_results: 最大结果数
            
        Returns:
            搜索结果列表
        """
        try:
            # DuckDuckGo Instant Answer API
            # 使用HTML接口获取搜索结果
            search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            
            http_utils = AsyncRequestUtils(
                ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                timeout=10
            )
            
            response = await http_utils.get(search_url)
            
            if not response:
                # 如果HTML接口失败，尝试使用API接口
                return await self._search_duckduckgo_api(query, max_results)
            
            # 解析HTML结果
            results = self._parse_duckduckgo_html(response, max_results)
            
            if results:
                return results
            
            # 如果HTML解析失败，尝试API接口
            return await self._search_duckduckgo_api(query, max_results)
            
        except Exception as e:
            logger.warning(f"DuckDuckGo HTML搜索失败: {e}，尝试API接口")
            return await self._search_duckduckgo_api(query, max_results)

    async def _search_duckduckgo_api(self, query: str, max_results: int) -> list:
        """
        使用DuckDuckGo API进行搜索（备用方案）
        
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
            
            http_utils = AsyncRequestUtils(timeout=10)
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
                            results.append({
                                "title": topic.get("Text", "").split(" - ")[0] if " - " in text else text[:50],
                                "snippet": text,
                                "url": first_url,
                                "source": "DuckDuckGo Related"
                            })
            
            return results[:max_results]
            
        except Exception as e:
            logger.warning(f"DuckDuckGo API搜索失败: {e}")
            # 如果DuckDuckGo失败，尝试使用Bing搜索（备用）
            return await self._search_bing_fallback(query, max_results)

    def _parse_duckduckgo_html(self, html: str, max_results: int) -> list:
        """
        解析DuckDuckGo HTML搜索结果
        
        Args:
            html: HTML内容
            max_results: 最大结果数
            
        Returns:
            搜索结果列表
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            
            # 尝试多种可能的HTML结构
            # 方法1: 查找class为"result"的div
            result_divs = soup.find_all('div', class_='result')
            if not result_divs:
                # 方法2: 查找class包含"result"的元素
                result_divs = soup.find_all('div', class_=re.compile(r'result'))
            if not result_divs:
                # 方法3: 查找包含链接的div，这些通常是搜索结果
                result_divs = soup.find_all('div', limit=max_results * 3)
            
            for div in result_divs[:max_results * 2]:  # 多查找一些，以便过滤
                try:
                    # 查找标题链接
                    title_elem = None
                    # 尝试多种可能的类名
                    for class_name in ['result__a', 'web-result__a', 'result-link', 'result__url']:
                        title_elem = div.find('a', class_=class_name)
                        if title_elem:
                            break
                    
                    # 如果没找到，尝试查找div内的第一个链接
                    if not title_elem:
                        title_elem = div.find('a')
                    
                    if not title_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    url = title_elem.get('href', '')
                    
                    # 清理URL（DuckDuckGo有时会添加重定向）
                    if url.startswith('/l/?kh=') or url.startswith('/l/?uddg='):
                        # 提取实际URL
                        parsed = urlparse(url)
                        query_params = parse_qs(parsed.query)
                        if 'uddg' in query_params:
                            url = query_params['uddg'][0]
                        elif 'u' in query_params:
                            url = query_params['u'][0]
                    
                    # 提取摘要
                    snippet = ""
                    for class_name in ['result__snippet', 'web-result__snippet', 'result__body']:
                        snippet_elem = div.find(class_=class_name)
                        if snippet_elem:
                            snippet = snippet_elem.get_text(strip=True)
                            break
                    
                    # 如果没找到摘要，尝试从div的文本中提取（排除标题）
                    if not snippet:
                        div_text = div.get_text(strip=True)
                        if title and title in div_text:
                            snippet = div_text.replace(title, '', 1).strip()
                        else:
                            snippet = div_text[:200]  # 限制长度
                    
                    if title and url and len(results) < max_results:
                        results.append({
                            "title": title,
                            "snippet": snippet,
                            "url": url,
                            "source": "DuckDuckGo"
                        })
                except Exception as e:
                    logger.debug(f"解析单个搜索结果失败: {e}")
                    continue
                
                if len(results) >= max_results:
                    break
            
            return results[:max_results]
            
        except Exception as e:
            logger.warning(f"解析DuckDuckGo HTML失败: {e}")
            return []

    async def _search_bing_fallback(self, query: str, max_results: int) -> list:
        """
        使用Bing搜索作为备用方案（简单实现）
        
        Args:
            query: 搜索查询
            max_results: 最大结果数
            
        Returns:
            搜索结果列表
        """
        try:
            # 使用Bing搜索（需要API密钥，这里仅作为示例）
            # 实际使用时可能需要配置API密钥
            logger.info("尝试使用Bing搜索作为备用方案")
            
            # 这里可以扩展实现Bing搜索
            # 目前返回空列表，让调用者知道搜索失败
            return []
            
        except Exception as e:
            logger.warning(f"Bing搜索失败: {e}")
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
