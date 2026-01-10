"""查询媒体详情工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.media import MediaChain
from app.log import logger
from app.schemas import MediaType


class QueryMediaDetailInput(BaseModel):
    """查询媒体详情工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    tmdb_id: int = Field(..., description="TMDB ID of the media (movie or TV series)")
    media_type: str = Field(..., description="Media type: 'movie' or 'tv'")


class QueryMediaDetailTool(MoviePilotTool):
    name: str = "query_media_detail"
    description: str = "Query detailed media information from TMDB by ID and media_type. IMPORTANT: Convert search results type: '电影'→'movie', '电视剧'→'tv'. Returns core metadata including title, year, overview, status, genres, directors, actors, and season count for TV series."
    args_schema: Type[BaseModel] = QueryMediaDetailInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        tmdb_id = kwargs.get("tmdb_id")
        return f"正在查询媒体详情: TMDB ID {tmdb_id}"

    async def run(self, tmdb_id: int, media_type: str, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: tmdb_id={tmdb_id}, media_type={media_type}")

        try:
            media_chain = MediaChain()

            mtype = None
            if media_type:
                if media_type.lower() == 'movie':
                    mtype = MediaType.MOVIE
                elif media_type.lower() == 'tv':
                    mtype = MediaType.TV

            mediainfo = await media_chain.async_recognize_media(tmdbid=tmdb_id, mtype=mtype)
            
            if not mediainfo:
                return json.dumps({
                    "success": False,
                    "message": f"未找到 TMDB ID {tmdb_id} 的媒体信息"
                }, ensure_ascii=False)

            # 精简 genres - 只保留名称
            genres = [g.get("name") for g in (mediainfo.genres or []) if g.get("name")]

            # 精简 directors - 只保留姓名和职位
            directors = [
                {
                    "name": d.get("name"),
                    "job": d.get("job")
                }
                for d in (mediainfo.directors or [])
                if d.get("name")
            ]

            # 精简 actors - 只保留姓名和角色
            actors = [
                {
                    "name": a.get("name"),
                    "character": a.get("character")
                }
                for a in (mediainfo.actors or [])
                if a.get("name")
            ]

            # 构建基础媒体详情信息
            result = {
                "success": True,
                "tmdb_id": tmdb_id,
                "type": mediainfo.type.value if mediainfo.type else None,
                "title": mediainfo.title,
                "year": mediainfo.year,
                "overview": mediainfo.overview,
                "status": mediainfo.status,
                "genres": genres,
                "directors": directors,
                "actors": actors
            }

            # 如果是电视剧，添加电视剧特有信息
            if mediainfo.type == MediaType.TV:
                # 精简 season_info - 只保留基础摘要
                season_info = [
                    {
                        "season_number": s.get("season_number"),
                        "name": s.get("name"),
                        "episode_count": s.get("episode_count"),
                        "air_date": s.get("air_date")
                    }
                    for s in (mediainfo.season_info or [])
                    if s.get("season_number") is not None
                ]

                result.update({
                    "number_of_seasons": mediainfo.number_of_seasons,
                    "number_of_episodes": mediainfo.number_of_episodes,
                    "first_air_date": mediainfo.first_air_date,
                    "last_air_date": mediainfo.last_air_date,
                    "season_info": season_info
                })

            return json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            error_message = f"查询媒体详情失败: {str(e)}"
            logger.error(f"查询媒体详情失败: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "message": error_message,
                "tmdb_id": tmdb_id
            }, ensure_ascii=False)
