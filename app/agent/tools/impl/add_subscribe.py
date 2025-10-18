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
        self._send_tool_message(f"正在添加订阅: {title} ({year}) - {media_type}", "info")
        
        try:
            subscribe_chain = SubscribeChain()
            sid, message = subscribe_chain.add(mtype=MediaType(media_type), title=title, year=year, 
                                             tmdbid=tmdb_id, season=season, username=self._user_id)
            if sid:
                success_message = f"成功添加订阅：{title} ({year})"
                self._send_tool_message(success_message, "success")
                return success_message
            else:
                error_message = f"添加订阅失败：{message}"
                self._send_tool_message(error_message, "error")
                return error_message
        except Exception as e:
            error_message = f"添加订阅时发生错误: {str(e)}"
            self._send_tool_message(error_message, "error")
            return error_message
