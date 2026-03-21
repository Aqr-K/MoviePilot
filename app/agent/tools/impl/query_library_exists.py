"""查询媒体库工具"""

import json
from collections import OrderedDict
from typing import Optional, Type, Any

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.helper.mediaserver import MediaServerHelper
from app.log import logger
from app.schemas.types import MediaType, media_type_to_agent


def _sort_seasons(seasons: Optional[dict]) -> dict:
    """按季号、集号升序整理季集信息，保证输出稳定。"""
    if not seasons:
        return {}

    def _sort_key(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return str(value)

    return OrderedDict(
        (season, sorted(episodes, key=_sort_key))
        for season, episodes in sorted(seasons.items(), key=lambda item: _sort_key(item[0]))
    )


def _filter_regular_seasons(seasons: Optional[dict]) -> OrderedDict:
    """仅保留正片季，忽略 season 0 等特殊季。"""
    sorted_seasons = _sort_seasons(seasons)
    regular_seasons = OrderedDict()
    for season, episodes in sorted_seasons.items():
        try:
            season_number = int(season)
        except (TypeError, ValueError):
            continue
        if season_number > 0:
            regular_seasons[season_number] = episodes
    return regular_seasons


def _build_tv_server_result(existing_seasons: OrderedDict, total_seasons: OrderedDict) -> dict[str, Any]:
    """构建单个服务器的电视剧存在性结果。"""
    seasons_result = OrderedDict()
    missing_seasons = []
    all_seasons = sorted(set(total_seasons.keys()) | set(existing_seasons.keys()))

    for season in all_seasons:
        existing_episodes = existing_seasons.get(season, [])
        total_episodes = total_seasons.get(season)
        if total_episodes is not None:
            missing_episodes = [episode for episode in total_episodes if episode not in existing_episodes]
            total_episode_count = len(total_episodes)
        else:
            missing_episodes = None
            total_episode_count = None
        seasons_result[str(season)] = {
            "existing_episodes": existing_episodes,
            "total_episodes": total_episode_count,
            "missing_episodes": missing_episodes
        }
        if total_episodes is not None and not existing_episodes:
            missing_seasons.append(season)

    return {
        "seasons": seasons_result,
        "missing_seasons": missing_seasons
    }


class QueryLibraryExistsInput(BaseModel):
    """查询媒体库工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    tmdb_id: Optional[int] = Field(None, description="TMDB ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    douban_id: Optional[str] = Field(None, description="Douban ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    media_type: Optional[str] = Field(None, description="Allowed values: movie, tv")


class QueryLibraryExistsTool(MoviePilotTool):
    name: str = "query_library_exists"
    description: str = "Check whether media already exists in Plex, Emby, or Jellyfin by media ID. Results are grouped by media server; TV results include existing episodes, total episodes, and missing episodes/seasons. Requires tmdb_id or douban_id from search_media."
    args_schema: Type[BaseModel] = QueryLibraryExistsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        tmdb_id = kwargs.get("tmdb_id")
        douban_id = kwargs.get("douban_id")
        media_type = kwargs.get("media_type")

        if tmdb_id:
            message = f"正在查询媒体库: TMDB={tmdb_id}"
        elif douban_id:
            message = f"正在查询媒体库: 豆瓣={douban_id}"
        else:
            message = "正在查询媒体库"
        if media_type:
            message += f" [{media_type}]"
        return message

    async def run(self, tmdb_id: Optional[int] = None, douban_id: Optional[str] = None,
                  media_type: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: tmdb_id={tmdb_id}, douban_id={douban_id}, media_type={media_type}")
        try:
            if not tmdb_id and not douban_id:
                return "参数错误：tmdb_id 和 douban_id 至少需要提供一个，请先使用 search_media 工具获取媒体 ID。"

            media_type_enum = None
            if media_type:
                media_type_enum = MediaType.from_agent(media_type)
                if not media_type_enum:
                    return f"错误：无效的媒体类型 '{media_type}'，支持的类型：'movie', 'tv'"

            media_chain = MediaServerChain()
            mediainfo = media_chain.recognize_media(
                tmdbid=tmdb_id,
                doubanid=douban_id,
                mtype=media_type_enum,
            )
            if not mediainfo:
                media_id = f"TMDB={tmdb_id}" if tmdb_id else f"豆瓣={douban_id}"
                return f"未识别到媒体信息: {media_id}"

            # 2. 遍历所有媒体服务器，分别查询存在性信息
            server_results = OrderedDict()
            media_server_helper = MediaServerHelper()
            total_seasons = _filter_regular_seasons(mediainfo.seasons)
            global_existsinfo = media_chain.media_exists(mediainfo=mediainfo)

            for service_name in sorted(media_server_helper.get_services().keys()):
                existsinfo = media_chain.media_exists(mediainfo=mediainfo, server=service_name)
                if not existsinfo:
                    continue

                if existsinfo.type == MediaType.TV:
                    existing_seasons = _filter_regular_seasons(existsinfo.seasons)
                    server_results[service_name] = _build_tv_server_result(
                        existing_seasons=existing_seasons,
                        total_seasons=total_seasons
                    )
                else:
                    server_results[service_name] = {
                        "exists": True
                    }

            if global_existsinfo:
                fallback_server_name = global_existsinfo.server or "local"
                if fallback_server_name not in server_results:
                    if global_existsinfo.type == MediaType.TV:
                        server_results[fallback_server_name] = _build_tv_server_result(
                            existing_seasons=_filter_regular_seasons(global_existsinfo.seasons),
                            total_seasons=total_seasons
                        )
                    else:
                        server_results[fallback_server_name] = {
                            "exists": True
                        }

            if not server_results:
                return "媒体库中未找到相关媒体"

            # 3. 组装统一的存在性结果，不查询媒体服务器详情
            result_dict = {
                "title": mediainfo.title,
                "year": mediainfo.year,
                "type": media_type_to_agent(mediainfo.type),
                "servers": server_results
            }

            return json.dumps([result_dict], ensure_ascii=False)
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"
