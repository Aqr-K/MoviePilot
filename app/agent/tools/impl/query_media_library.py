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
    media_type: Optional[str] = Field("all", description="Type of media content: '电影' for films, '电视剧' for television series or anime series, 'all' for all types")
    title: Optional[str] = Field(None, description="Specific media title to search for (optional, if provided returns detailed info for that specific media)")
    year: Optional[str] = Field(None, description="Release year of the media (optional, helps narrow down search results)")


class QueryMediaLibraryTool(MoviePilotTool):
    name: str = "query_media_library"
    description: str = "Query media library status and list all media files that have been successfully processed and added to the media server (Plex, Emby, Jellyfin). Shows library statistics and file details."
    args_schema: Type[BaseModel] = QueryMediaLibraryInput

    async def _arun(self, media_type: Optional[str] = "all",
                    title: Optional[str] = None, year: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: media_type={media_type}, title={title}")
        try:
            media_server_oper = MediaServerOper()
            filtered_medias: List[MediaServerItem] = media_server_oper.exists(title=title, year=year, mtype=media_type)
            if filtered_medias:
                return json.dumps([m.to_dict() for m in filtered_medias])
            return "媒体库中未找到相关媒体。"
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"
