"""查询媒体库工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.log import logger
from app.schemas.types import MediaType


class QueryLibraryExistsInput(BaseModel):
    """查询媒体库工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    tmdb_id: Optional[int] = Field(None, description="TMDB ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    douban_id: Optional[str] = Field(None, description="Douban ID (can be obtained from search_media tool). Either tmdb_id or douban_id must be provided.")
    media_type: Optional[str] = Field(None, description="Allowed values: movie, tv")


class QueryLibraryExistsTool(MoviePilotTool):
    name: str = "query_library_exists"
    description: str = "Check whether a specific media resource already exists in the media library (Plex, Emby, Jellyfin) by media ID. Requires tmdb_id or douban_id (can be obtained from search_media tool) for accurate matching."
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
                media_type_key = media_type.strip().lower()
                if media_type_key == "movie":
                    media_type_enum = MediaType.MOVIE
                elif media_type_key == "tv":
                    media_type_enum = MediaType.TV
                else:
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

            # 2. 调用媒体服务器接口实时查询存在信息
            existsinfo = media_chain.media_exists(mediainfo=mediainfo)

            if not existsinfo:
                return "媒体库中未找到相关媒体"

            # 3. 如果找到了，获取详细信息并组装结果
            result_items = []
            if existsinfo.itemid and existsinfo.server:
                iteminfo = media_chain.iteminfo(server=existsinfo.server, item_id=existsinfo.itemid)
                if iteminfo:
                    # 使用 model_dump() 转换为字典格式
                    item_dict = iteminfo.model_dump(exclude_none=True)

                    # 对于电视剧，补充已存在的季集详情及进度统计
                    if existsinfo.type == MediaType.TV:
                        # 注入已存在集信息 (Dict[int, list])
                        item_dict["seasoninfo"] = existsinfo.seasons

                        # 统计库中已存在的季集总数
                        if existsinfo.seasons:
                            item_dict["existing_episodes_count"] = sum(len(e) for e in existsinfo.seasons.values())
                            item_dict["seasons_existing_count"] = {str(s): len(e) for s, e in existsinfo.seasons.items()}

                            # 如果识别到了元数据，补充总计对比和进度概览
                            if mediainfo.seasons:
                                item_dict["seasons_total_count"] = {str(s): len(e) for s, e in mediainfo.seasons.items()}
                                # 进度概览，例如 "Season 1": "3/12"
                                item_dict["seasons_progress"] = {
                                    f"第{s}季": f"{len(existsinfo.seasons.get(s, []))}/{len(mediainfo.seasons.get(s, []))} 集"
                                    for s in mediainfo.seasons.keys() if (s in existsinfo.seasons or s > 0)
                                }

                    result_items.append(item_dict)

            if result_items:
                return json.dumps(result_items, ensure_ascii=False)

            # 如果找到了但没有获取到 iteminfo，返回基本信息
            result_dict = {
                "title": mediainfo.title,
                "year": mediainfo.year,
                "type": existsinfo.type.value if existsinfo.type else None,
                "server": existsinfo.server,
                "server_type": existsinfo.server_type,
                "itemid": existsinfo.itemid,
                "seasons": existsinfo.seasons if existsinfo.seasons else {}
            }
            if existsinfo.type == MediaType.TV and existsinfo.seasons:
                result_dict["existing_episodes_count"] = sum(len(e) for e in existsinfo.seasons.values())
                result_dict["seasons_existing_count"] = {str(s): len(e) for s, e in existsinfo.seasons.items()}
                if mediainfo.seasons:
                    result_dict["seasons_total_count"] = {str(s): len(e) for s, e in mediainfo.seasons.items()}

            return json.dumps([result_dict], ensure_ascii=False)
        except Exception as e:
            logger.error(f"查询媒体库失败: {e}", exc_info=True)
            return f"查询媒体库时发生错误: {str(e)}"

