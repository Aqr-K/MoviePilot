"""查询媒体库工具"""

import json
from typing import Optional, List, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db.mediaserver_oper import MediaServerOper
from app.log import logger
from app.schemas import MediaServerItem


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
            media_server_oper = MediaServerOper()
            filtered_medias: List[MediaServerItem] = await media_server_oper.async_exists(title=title, year=year, mtype=media_type)
            if filtered_medias:
                return json.dumps([m.to_dict() for m in filtered_medias])
            return "媒体库中未找到相关媒体"
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"
