"""添加订阅工具"""

from typing import Optional

from app.chain.subscribe import SubscribeChain
from app.log import logger
from app.schemas.types import MediaType
from app.agent.tools.base import MoviePilotTool


class AddSubscribeTool(MoviePilotTool):
    name: str = "add_subscribe"
    description: str = "添加媒体订阅，为用户感兴趣的媒体内容创建订阅规则。"

    async def _arun(self, title: str, year: str, media_type: str, explanation: str, 
                    season: Optional[int] = None, tmdb_id: Optional[str] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: title={title}, year={year}, media_type={media_type}, season={season}, tmdb_id={tmdb_id}")
        
        # 发送工具执行说明
        self._send_tool_message(f"正在添加订阅: {title} ({year}) - {media_type}", title="添加订阅")
        
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
                self._send_tool_message(success_message, title="订阅成功")
                return success_message
            else:
                error_message = f"添加订阅失败：{message}"
                self._send_tool_message(error_message, title="订阅失败")
                return error_message
        except Exception as e:
            error_message = f"添加订阅时发生错误: {str(e)}"
            logger.error(f"添加订阅失败: {e}", exc_info=True)
            self._send_tool_message(error_message, title="订阅失败")
            return error_message
