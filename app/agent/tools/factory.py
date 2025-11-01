"""MoviePilot工具工厂"""

from typing import List, Callable

from app.agent.tools.impl.add_download import AddDownloadTool
from app.agent.tools.impl.add_subscribe import AddSubscribeTool
from app.agent.tools.impl.get_recommendations import GetRecommendationsTool
from app.agent.tools.impl.query_downloaders import QueryDownloadersTool
from app.agent.tools.impl.query_downloads import QueryDownloadsTool
from app.agent.tools.impl.query_media_library import QueryMediaLibraryTool
from app.agent.tools.impl.query_subscribes import QuerySubscribesTool
from app.agent.tools.impl.search_media import SearchMediaTool
from app.agent.tools.impl.search_torrents import SearchTorrentsTool
from app.agent.tools.impl.send_message import SendMessageTool
from app.log import logger
from .base import MoviePilotTool


class MoviePilotToolFactory:
    """MoviePilot工具工厂"""

    @staticmethod
    def create_tools(session_id: str, user_id: str,
                     channel: str = None, source: str = None, username: str = None,
                     callback_handler: Callable = None) -> List[MoviePilotTool]:
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
            tool = ToolClass(
                session_id=session_id,
                user_id=user_id
            )
            tool.set_message_attr(channel=channel, source=source, username=username)
            tool.set_callback_handler(callback_handler=callback_handler)
            tools.append(tool)
        logger.info(f"成功创建 {len(tools)} 个MoviePilot工具")
        return tools
