"""添加订阅工具"""

from typing import Optional, Type, List

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
    media_type: str = Field(...,
                            description="Type of media content: '电影' for films, '电视剧' for television series or anime series")
    season: Optional[int] = Field(None,
                                  description="Season number for TV shows (optional, if not specified will subscribe to all seasons)")
    tmdb_id: Optional[str] = Field(None,
                                   description="TMDB database ID for precise media identification (optional but recommended for accuracy)")
    start_episode: Optional[int] = Field(None,
                                          description="Starting episode number for TV shows (optional, defaults to 1 if not specified)")
    total_episode: Optional[int] = Field(None,
                                          description="Total number of episodes for TV shows (optional, will be auto-detected from TMDB if not specified)")
    quality: Optional[str] = Field(None,
                                   description="Quality filter as regular expression (optional, e.g., 'BluRay|WEB-DL|HDTV')")
    resolution: Optional[str] = Field(None,
                                      description="Resolution filter as regular expression (optional, e.g., '1080p|720p|2160p')")
    effect: Optional[str] = Field(None,
                                  description="Effect filter as regular expression (optional, e.g., 'HDR|DV|SDR')")
    filter_groups: Optional[List[str]] = Field(None,
                                               description="List of filter rule group names to apply (optional, use query_rule_groups tool to get available rule groups)")
    sites: Optional[List[int]] = Field(None,
                                       description="List of site IDs to search from (optional, use query_sites tool to get available site IDs)")


class AddSubscribeTool(MoviePilotTool):
    name: str = "add_subscribe"
    description: str = "Add media subscription to create automated download rules for movies and TV shows. The system will automatically search and download new episodes or releases based on the subscription criteria. Supports advanced filtering options like quality, resolution, and effect filters using regular expressions."
    args_schema: Type[BaseModel] = AddSubscribeInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据订阅参数生成友好的提示消息"""
        title = kwargs.get("title", "")
        year = kwargs.get("year", "")
        media_type = kwargs.get("media_type", "")
        season = kwargs.get("season")
        
        message = f"正在添加订阅: {title}"
        if year:
            message += f" ({year})"
        if media_type:
            message += f" [{media_type}]"
        if season:
            message += f" 第{season}季"
        
        return message

    async def run(self, title: str, year: str, media_type: str,
                  season: Optional[int] = None, tmdb_id: Optional[str] = None,
                  start_episode: Optional[int] = None, total_episode: Optional[int] = None,
                  quality: Optional[str] = None, resolution: Optional[str] = None,
                  effect: Optional[str] = None, filter_groups: Optional[List[str]] = None,
                  sites: Optional[List[int]] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, "
            f"season={season}, tmdb_id={tmdb_id}, start_episode={start_episode}, "
            f"total_episode={total_episode}, quality={quality}, resolution={resolution}, "
            f"effect={effect}, filter_groups={filter_groups}, sites={sites}")

        try:
            subscribe_chain = SubscribeChain()
            # 转换 tmdb_id 为整数
            tmdbid_int = None
            if tmdb_id:
                try:
                    tmdbid_int = int(tmdb_id)
                except (ValueError, TypeError):
                    logger.warning(f"无效的 tmdb_id: {tmdb_id}，将忽略")

            # 构建额外的订阅参数
            subscribe_kwargs = {}
            if start_episode is not None:
                subscribe_kwargs['start_episode'] = start_episode
            if total_episode is not None:
                subscribe_kwargs['total_episode'] = total_episode
            if quality:
                subscribe_kwargs['quality'] = quality
            if resolution:
                subscribe_kwargs['resolution'] = resolution
            if effect:
                subscribe_kwargs['effect'] = effect
            if filter_groups:
                subscribe_kwargs['filter_groups'] = filter_groups
            if sites:
                subscribe_kwargs['sites'] = sites

            sid, message = await subscribe_chain.async_add(
                mtype=MediaType(media_type),
                title=title,
                year=year,
                tmdbid=tmdbid_int,
                season=season,
                username=self._user_id,
                **subscribe_kwargs
            )
            if sid:
                if message and "已存在" in message:
                    return f"订阅已存在：{title} ({year})。如需修改参数请先删除旧订阅。"

                result_msg = f"成功添加订阅：{title} ({year})"
                if subscribe_kwargs:
                    params = []
                    if start_episode is not None:
                        params.append(f"开始集数: {start_episode}")
                    if total_episode is not None:
                        params.append(f"总集数: {total_episode}")
                    if quality:
                        params.append(f"质量过滤: {quality}")
                    if resolution:
                        params.append(f"分辨率过滤: {resolution}")
                    if effect:
                        params.append(f"特效过滤: {effect}")
                    if filter_groups:
                        params.append(f"规则组: {', '.join(filter_groups)}")
                    if sites:
                        params.append(f"站点: {', '.join(map(str, sites))}")
                    if params:
                        result_msg += f"\n配置参数: {', '.join(params)}"
                return result_msg
            else:
                return f"添加订阅失败：{message}"
        except Exception as e:
            logger.error(f"添加订阅失败: {e}", exc_info=True)
            return f"添加订阅时发生错误: {str(e)}"
