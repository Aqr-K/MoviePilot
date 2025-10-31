"""搜索媒体工具"""

import json
from typing import Optional

from app.chain.media import MediaChain
from app.core.metainfo import MetaInfo
from app.log import logger
from app.schemas.types import MediaType
from app.agent.tools.base import MoviePilotTool


class SearchMediaTool(MoviePilotTool):
    name: str = "search_media"
    description: str = "搜索媒体资源，包括电影、电视剧、动漫等。可以根据标题、年份、类型等条件进行搜索。"

    async def _arun(self, title: str, explanation: str, year: Optional[str] = None, 
                    media_type: Optional[str] = None, season: Optional[int] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}")
        
        # 发送工具执行说明
        self._send_tool_message(f"正在搜索媒体资源: {title}" + (f" ({year})" if year else ""), title="搜索中")
        
        try:
            media_chain = MediaChain()
            # 构建搜索标题
            search_title = title
            if year:
                search_title = f"{title} {year}"
            if media_type:
                search_title = f"{search_title} {media_type}"
            if season:
                search_title = f"{search_title} S{season:02d}"
            
            # 使用 MediaChain.search 方法
            meta, results = media_chain.search(title=search_title)
            
            # 过滤结果
            if results:
                filtered_results = []
                for result in results:
                    if year and result.year != year:
                        continue
                    if media_type:
                        try:
                            if result.type != MediaType(media_type):
                                continue
                        except:
                            pass
                    if season and result.season != season:
                        continue
                    filtered_results.append(result)
                
                if filtered_results:
                    result_message = f"找到 {len(filtered_results)} 个相关媒体资源"
                    self._send_tool_message(result_message, title="搜索成功")
                    
                    # 发送详细结果
                    for i, result in enumerate(filtered_results[:5]):  # 只显示前5个结果
                        media_info = f"{i+1}. {result.title} ({result.year}) - {result.type.value if result.type else '未知'}"
                        self._send_tool_message(media_info, title="搜索结果")
                    
                    return json.dumps([r.to_dict() for r in filtered_results], ensure_ascii=False, indent=2)
                else:
                    error_message = f"未找到符合条件的媒体资源: {title}"
                    self._send_tool_message(error_message, title="搜索完成")
                    return error_message
            else:
                error_message = f"未找到相关媒体资源: {title}"
                self._send_tool_message(error_message, title="搜索完成")
                return error_message
        except Exception as e:
            error_message = f"搜索媒体失败: {str(e)}"
            logger.error(f"搜索媒体失败: {e}", exc_info=True)
            self._send_tool_message(error_message, title="搜索失败")
            return error_message
