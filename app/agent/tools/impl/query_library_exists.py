"""查询媒体库工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.mediaserver import MediaServerChain
from app.core.context import MediaInfo
from app.core.meta import MetaBase
from app.log import logger
from app.schemas.types import MediaType


class QueryLibraryExistsInput(BaseModel):
    """查询媒体库工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    media_type: Optional[str] = Field("all",
                                      description="Type of media content: '电影' for films, '电视剧' for television series or anime series, 'all' for all types")
    title: Optional[str] = Field(None,
                                 description="Specific media title to check if it exists in the media library (optional, if provided checks for that specific media)")
    year: Optional[str] = Field(None,
                                description="Release year of the media (optional, helps narrow down search results)")


class QueryLibraryExistsTool(MoviePilotTool):
    name: str = "query_library_exists"
    description: str = "Check if a specific media resource already exists in the media library (Plex, Emby, Jellyfin). Use this tool to verify whether a movie or TV series has been successfully processed and added to the media server before performing operations like downloading or subscribing."
    args_schema: Type[BaseModel] = QueryLibraryExistsInput

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

            media_chain = MediaServerChain()

            # 1. 识别媒体信息（获取 TMDB ID 和各季的总集数等元数据）
            meta = MetaBase(title=title)
            if year:
                meta.year = str(year)
            if media_type == "电影":
                meta.type = MediaType.MOVIE
            elif media_type == "电视剧":
                meta.type = MediaType.TV

            # 使用识别方法补充信息
            recognize_info = media_chain.recognize_media(meta=meta)
            if recognize_info:
                mediainfo = recognize_info
            else:
                # 识别失败，创建基本信息的 MediaInfo
                mediainfo = MediaInfo()
                mediainfo.title = title
                mediainfo.year = year
                if media_type == "电影":
                    mediainfo.type = MediaType.MOVIE
                elif media_type == "电视剧":
                    mediainfo.type = MediaType.TV

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

