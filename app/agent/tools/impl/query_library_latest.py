"""查询媒体服务器最近入库影片工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.helper.service import ServiceConfigHelper
from app.log import logger

PAGE_SIZE = 20


class QueryLibraryLatestInput(BaseModel):
    """查询媒体服务器最近入库影片工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )
    server: Optional[str] = Field(
        None,
        description="Media server name (optional, if not specified queries all enabled media servers)",
    )
    page: Optional[int] = Field(
        1, description="Page number for pagination (default: 1, 20 items per page)"
    )


class QueryLibraryLatestTool(MoviePilotTool):
    name: str = "query_library_latest"
    description: str = "Query the latest media items added to the media server (Plex, Emby, Jellyfin). Returns recently added movies and TV series with their titles, images, links, and other metadata. Supports pagination with 20 items per page."
    args_schema: Type[BaseModel] = QueryLibraryLatestInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        server = kwargs.get("server")
        page = kwargs.get("page", 1)

        parts = ["正在查询媒体服务器最近入库影片"]

        if server:
            parts.append(f"服务器: {server}")
        else:
            parts.append("所有服务器")

        parts.append(f"第{page}页")

        return " | ".join(parts)

    async def run(
        self, server: Optional[str] = None, page: Optional[int] = 1, **kwargs
    ) -> str:
        page = max(1, page or 1)
        # 为了支持分页，需要获取足够多的数据再切片
        fetch_count = page * PAGE_SIZE
        logger.info(f"执行工具: {self.name}, 参数: server={server}, page={page}")
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
                    latest_items = media_chain.latest(
                        server=server_name, count=fetch_count, username=self._username
                    )
                    if latest_items:
                        for item in latest_items:
                            item_dict = item.model_dump(exclude_none=True)
                            item_dict["server"] = server_name
                            results.append(item_dict)
            else:
                # 查询指定服务器
                latest_items = media_chain.latest(
                    server=server, count=fetch_count, username=self._username
                )
                if latest_items:
                    for item in latest_items:
                        item_dict = item.model_dump(exclude_none=True)
                        item_dict["server"] = server
                        results.append(item_dict)

            if not results:
                server_info = f"服务器 {server}" if server else "所有服务器"
                return f"未找到 {server_info} 的最近入库影片"

            # 分页
            total_count = len(results)
            start = (page - 1) * PAGE_SIZE
            end = start + PAGE_SIZE
            page_results = results[start:end]

            if not page_results:
                total_pages = (total_count + PAGE_SIZE - 1) // PAGE_SIZE
                return f"第 {page} 页没有数据，共 {total_count} 条结果，共 {total_pages} 页。"

            total_pages = (total_count + PAGE_SIZE - 1) // PAGE_SIZE
            payload_msg = f"第 {page}/{total_pages} 页，当前页 {len(page_results)} 条结果，共 {total_count} 条。"
            if page < total_pages:
                payload_msg += f" 可使用 page={page + 1} 获取下一页。"

            result_json = json.dumps(page_results, ensure_ascii=False, indent=2)
            return f"{payload_msg}\n\n{result_json}"

        except Exception as e:
            logger.error(f"查询媒体服务器最近入库影片失败: {e}", exc_info=True)
            return f"查询媒体服务器最近入库影片时发生错误: {str(e)}"
