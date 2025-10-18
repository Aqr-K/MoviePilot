"""搜索种子工具"""

import json
from typing import List, Optional

from app.chain.search import SearchChain
from app.log import logger
from app.schemas.types import MediaType
from app.agent.tools.base import MoviePilotTool


class SearchTorrentsTool(MoviePilotTool):
    name: str = "search_torrents"
    description: str = "搜索站点种子资源，根据媒体信息搜索可下载的种子文件。"

    async def _arun(self, title: str, explanation: str, year: Optional[str] = None, 
                    media_type: Optional[str] = None, season: Optional[int] = None, 
                    sites: Optional[List[int]] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, sites={sites}")
        
        # 发送工具执行说明
        self._send_tool_message(f"正在搜索种子资源: {title}" + (f" ({year})" if year else ""), "info")
        
        try:
            search_chain = SearchChain()
            torrents = search_chain.search_by_title(title=title, sites=sites)
            filtered_torrents = []
            for torrent in torrents:
                if year and torrent.meta_info.year != year:
                    continue
                if media_type and torrent.media_info and torrent.media_info.type != MediaType(media_type):
                    continue
                if season and torrent.meta_info.begin_season != season:
                    continue
                filtered_torrents.append(torrent)
            
            if filtered_torrents:
                result_message = f"找到 {len(filtered_torrents)} 个相关种子资源"
                self._send_tool_message(result_message, "success")
                
                # 发送详细结果
                for i, torrent in enumerate(filtered_torrents[:5]):  # 只显示前5个结果
                    torrent_info = f"{i+1}. {torrent.title} - {torrent.site_name}"
                    self._send_tool_message(torrent_info, "info")
                
                return json.dumps([t.dict() for t in filtered_torrents], ensure_ascii=False, indent=2)
            else:
                error_message = f"未找到相关种子资源: {title}"
                self._send_tool_message(error_message, "warning")
                return error_message
        except Exception as e:
            error_message = f"搜索种子时发生错误: {str(e)}"
            self._send_tool_message(error_message, "error")
            return error_message
