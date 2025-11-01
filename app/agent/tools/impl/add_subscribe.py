"""添加订阅工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.subscribe import SubscribeChain
from app.log import logger
from app.schemas.types import MediaType


class AddSubscribeInput(BaseModel):
    """添加订阅工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    title: str = Field(..., description="The title of the media to subscribe to (e.g., 'The Matrix', 'Breaking Bad')")
    year: str = Field(..., description="Release year of the media (required for accurate identification)")
    media_type: str = Field(..., description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None, description="Season number for TV shows (optional, if not specified will subscribe to all seasons)")
    tmdb_id: Optional[str] = Field(None, description="TMDB database ID for precise media identification (optional but recommended for accuracy)")


class AddSubscribeTool(MoviePilotTool):
    name: str = "add_subscribe"
    description: str = "Add media subscription to create automated download rules for movies and TV shows. The system will automatically search and download new episodes or releases based on the subscription criteria."
    args_schema: Type[BaseModel] = AddSubscribeInput

    async def _arun(self, title: str, year: str, media_type: str,
                    season: Optional[int] = None, tmdb_id: Optional[str] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, tmdb_id={tmdb_id}")

        # 发送工具执行说明
        self.send_tool_message(f"正在添加订阅: {title} ({year}) - {media_type}", title="添加订阅")

        try:
            subscribe_chain = SubscribeChain()
            # 转换 tmdb_id 为整数
            tmdbid_int = None
            if tmdb_id:
                try:
                    tmdbid_int = int(tmdb_id)
                except (ValueError, TypeError):
                    logger.warning(f"无效的 tmdb_id: {tmdb_id}，将忽略")

            sid, message = subscribe_chain.add(
                mtype=MediaType(media_type),
                title=title,
                year=year,
                tmdbid=tmdbid_int,
                season=season,
                username=self._user_id
            )
            if sid:
                success_message = f"成功添加订阅：{title} ({year})"
                self.send_tool_message(success_message, title="订阅成功")
                return success_message
            else:
                error_message = f"添加订阅失败：{message}"
                self.send_tool_message(error_message, title="订阅失败")
                return error_message
        except Exception as e:
            error_message = f"添加订阅时发生错误: {str(e)}"
            logger.error(f"添加订阅失败: {e}", exc_info=True)
            self.send_tool_message(error_message, title="订阅失败")
            return error_message
