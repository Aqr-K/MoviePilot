"""MoviePilot工具工厂"""

from typing import List

from app.helper.message import MessageHelper
from app.log import logger
from .base import MoviePilotTool
from app.agent.tools.impl.search_media import SearchMediaTool
from app.agent.tools.impl.add_subscribe import AddSubscribeTool
from app.agent.tools.impl.search_torrents import SearchTorrentsTool
from app.agent.tools.impl.add_download import AddDownloadTool
from app.agent.tools.impl.query_subscribes import QuerySubscribesTool
from app.agent.tools.impl.query_downloads import QueryDownloadsTool
from app.agent.tools.impl.query_downloaders import QueryDownloadersTool
from app.agent.tools.impl.get_recommendations import GetRecommendationsTool
from app.agent.tools.impl.query_media_library import QueryMediaLibraryTool
from app.agent.tools.impl.send_message import SendMessageTool


class MoviePilotToolFactory:
    """MoviePilot工具工厂"""

    @staticmethod
    def create_tools(session_id: str, user_id: str, message_helper: MessageHelper = None) -> List[MoviePilotTool]:
        """创建MoviePilot工具列表"""
        tools = []
        tool_definitions = [
            SearchMediaTool,
            AddSubscribeTool,
            SearchTorrentsTool,
            AddDownloadTool,
            QuerySubscribesTool,
            QueryDownloadsTool,
            QueryDownloadersTool,
            GetRecommendationsTool,
            QueryMediaLibraryTool,
            SendMessageTool
        ]
        for ToolClass in tool_definitions:
            tools.append(ToolClass(
                session_id=session_id,
                user_id=user_id,
                message_helper=message_helper
            ))
        logger.info(f"成功创建 {len(tools)} 个MoviePilot工具")
        return tools
