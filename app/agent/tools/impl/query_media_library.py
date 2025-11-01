"""查询媒体库工具"""

import json
from typing import Optional

from app.db.mediaserver_oper import MediaServerOper
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class QueryMediaLibraryTool(MoviePilotTool):
    name: str = "query_media_library"
    description: str = "查询媒体库状态，查看已入库的媒体文件情况。"

    async def _arun(self, explanation: str, media_type: Optional[str] = "all", 
                    title: Optional[str] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: media_type={media_type}, title={title}")
        try:
            media_server_oper = MediaServerOper()
            medias = media_server_oper.list()
            filtered_medias = []
            for media in medias:
                if media_type != "all" and media.type != media_type:
                    continue
                if title and title.lower() not in media.title.lower():
                    continue
                filtered_medias.append(media)
            if filtered_medias:
                return json.dumps([m.to_dict() for m in filtered_medias])
            return "媒体库中未找到相关媒体。"
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"
