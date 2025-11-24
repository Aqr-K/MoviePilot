"""查询媒体库工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.core.context import MediaInfo
from app.log import logger
from app.schemas.types import MediaType


class QueryMediaLibraryInput(BaseModel):
    """查询媒体库工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    media_type: Optional[str] = Field("all",
                                      description="Type of media content: '电影' for films, '电视剧' for television series or anime series, 'all' for all types")
    title: Optional[str] = Field(None,
                                 description="Specific media title to check if it exists in the media library (optional, if provided checks for that specific media)")
    year: Optional[str] = Field(None,
                                description="Release year of the media (optional, helps narrow down search results)")


class QueryMediaLibraryTool(MoviePilotTool):
    name: str = "query_media_library"
    description: str = "Check if a specific media resource already exists in the media library (Plex, Emby, Jellyfin). Use this tool to verify whether a movie or TV series has been successfully processed and added to the media server before performing operations like downloading or subscribing."
    args_schema: Type[BaseModel] = QueryMediaLibraryInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        media_type = kwargs.get("media_type", "all")
        title = kwargs.get("title")
        year = kwargs.get("year")
        
        parts = ["正在查询媒体库"]
        
        if title:
            parts.append(f"标题: {title}")
        if year:
            parts.append(f"年份: {year}")
        if media_type != "all":
            parts.append(f"类型: {media_type}")
        
        return " | ".join(parts) if len(parts) > 1 else parts[0]

    async def run(self, media_type: Optional[str] = "all",
                  title: Optional[str] = None, year: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: media_type={media_type}, title={title}")
        try:
            if not title:
                return "请提供媒体标题进行查询"
            
            # 创建 MediaInfo 对象
            mediainfo = MediaInfo()
            mediainfo.title = title
            mediainfo.year = year
            
            # 转换媒体类型
            if media_type == "电影":
                mediainfo.type = MediaType.MOVIE
            elif media_type == "电视剧":
                mediainfo.type = MediaType.TV
            # media_type == "all" 时不设置类型，让媒体服务器自动判断
            
            # 调用媒体服务器接口实时查询
            media_chain = MediaServerChain()
            existsinfo = media_chain.media_exists(mediainfo=mediainfo)
            
            if not existsinfo:
                return "媒体库中未找到相关媒体"
            
            # 如果找到了，获取详细信息
            result_items = []
            if existsinfo.itemid and existsinfo.server:
                iteminfo = media_chain.iteminfo(server=existsinfo.server, item_id=existsinfo.itemid)
                if iteminfo:
                    # 使用 model_dump() 转换为字典格式
                    item_dict = iteminfo.model_dump(exclude_none=True)
                    result_items.append(item_dict)
            
            if result_items:
                return json.dumps(result_items, ensure_ascii=False)
            
            # 如果找到了但没有详细信息，返回基本信息
            result_dict = {
                "type": existsinfo.type.value if existsinfo.type else None,
                "server": existsinfo.server,
                "server_type": existsinfo.server_type,
                "itemid": existsinfo.itemid,
                "seasons": existsinfo.seasons if existsinfo.seasons else {}
            }
            return json.dumps([result_dict], ensure_ascii=False)
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"
