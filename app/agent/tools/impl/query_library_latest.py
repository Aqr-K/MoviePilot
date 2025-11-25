"""查询媒体服务器最近入库影片工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.helper.service import ServiceConfigHelper
from app.log import logger


class QueryLibraryLatestInput(BaseModel):
    """查询媒体服务器最近入库影片工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    server: Optional[str] = Field(None, description="Media server name (optional, if not specified queries all enabled media servers)")
    count: Optional[int] = Field(20, description="Number of items to return (default: 20)")


class QueryLibraryLatestTool(MoviePilotTool):
    name: str = "query_library_latest"
    description: str = "Query the latest media items added to the media server (Plex, Emby, Jellyfin). Returns recently added movies and TV series with their titles, images, links, and other metadata."
    args_schema: Type[BaseModel] = QueryLibraryLatestInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        server = kwargs.get("server")
        count = kwargs.get("count", 20)
        
        parts = ["正在查询媒体服务器最近入库影片"]
        
        if server:
            parts.append(f"服务器: {server}")
        else:
            parts.append("所有服务器")
        
        parts.append(f"数量: {count}条")
        
        return " | ".join(parts)

    async def run(self, server: Optional[str] = None, count: Optional[int] = 20, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: server={server}, count={count}")
        try:
            media_chain = MediaServerChain()
            results = []
            
            # 如果没有指定服务器，获取所有启用的媒体服务器
            if not server:
                mediaservers = ServiceConfigHelper.get_mediaserver_configs()
                enabled_servers = [ms.name for ms in mediaservers if ms.enabled]
                
                if not enabled_servers:
                    return "未找到启用的媒体服务器"
                
                # 遍历所有启用的服务器
                for server_name in enabled_servers:
                    latest_items = media_chain.latest(server=server_name, count=count, username=self._username)
                    if latest_items:
                        for item in latest_items:
                            item_dict = item.model_dump(exclude_none=True)
                            item_dict["server"] = server_name
                            results.append(item_dict)
            else:
                # 查询指定服务器
                latest_items = media_chain.latest(server=server, count=count, username=self._username)
                if latest_items:
                    for item in latest_items:
                        item_dict = item.model_dump(exclude_none=True)
                        item_dict["server"] = server
                        results.append(item_dict)
            
            if not results:
                server_info = f"服务器 {server}" if server else "所有服务器"
                return f"未找到 {server_info} 的最近入库影片"
            
            # 限制返回数量，避免结果过多
            if len(results) > count:
                results = results[:count]
            
            return json.dumps(results, ensure_ascii=False, indent=2)
            
        except Exception as e:
            logger.error(f"查询媒体服务器最近入库影片失败: {e}", exc_info=True)
            return f"查询媒体服务器最近入库影片时发生错误: {str(e)}"

