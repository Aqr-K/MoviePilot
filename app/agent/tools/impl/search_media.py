"""搜索媒体工具"""

import json
from typing import Optional

from app.chain.media import MediaChain
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class SearchMediaTool(MoviePilotTool):
    name: str = "search_media"
    description: str = "搜索媒体资源，包括电影、电视剧、动漫等。可以根据标题、年份、类型等条件进行搜索。"

    async def _arun(self, title: str, explanation: str, year: Optional[str] = None, 
                    media_type: Optional[str] = None, season: Optional[int] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}")
        
        # 发送工具执行说明
        self._send_tool_message(f"正在搜索媒体资源: {title}" + (f" ({year})" if year else ""), "info")
        
        try:
            media_chain = MediaChain()
            results = media_chain.search_media(title=title, year=year, mtype=media_type, season=season)
            if results:
                result_message = f"找到 {len(results)} 个相关媒体资源"
                self._send_tool_message(result_message, "success")
                
                # 发送详细结果
                for i, result in enumerate(results[:5]):  # 只显示前5个结果
                    media_info = f"{i+1}. {result.title} ({result.year}) - {result.type}"
                    self._send_tool_message(media_info, "info")
                
                return json.dumps([r.dict() for r in results], ensure_ascii=False, indent=2)
            else:
                error_message = f"未找到相关媒体资源: {title}"
                self._send_tool_message(error_message, "warning")
                return error_message
        except Exception as e:
            error_message = f"搜索媒体失败: {str(e)}"
            self._send_tool_message(error_message, "error")
            return error_message
