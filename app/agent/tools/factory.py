"""MoviePilot工具工厂"""

from typing import List, Callable

from app.agent.tools.impl.add_download import AddDownloadTool
from app.agent.tools.impl.add_subscribe import AddSubscribeTool
from app.agent.tools.impl.get_recommendations import GetRecommendationsTool
from app.agent.tools.impl.query_downloaders import QueryDownloadersTool
from app.agent.tools.impl.query_downloads import QueryDownloadsTool
from app.agent.tools.impl.query_media_library import QueryMediaLibraryTool
from app.agent.tools.impl.query_sites import QuerySitesTool
from app.agent.tools.impl.query_subscribes import QuerySubscribesTool
from app.agent.tools.impl.search_media import SearchMediaTool
from app.agent.tools.impl.search_torrents import SearchTorrentsTool
from app.agent.tools.impl.send_message import SendMessageTool
from app.core.plugin import PluginManager
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
            QuerySitesTool,
            GetRecommendationsTool,
            QueryMediaLibraryTool,
            SendMessageTool
        ]
        # 创建内置工具
        for ToolClass in tool_definitions:
            tool = ToolClass(
                session_id=session_id,
                user_id=user_id
            )
            tool.set_message_attr(channel=channel, source=source, username=username)
            tool.set_callback_handler(callback_handler=callback_handler)
            tools.append(tool)
        
        # 加载插件提供的工具
        plugin_tools_count = 0
        plugin_tools_info = PluginManager().get_plugin_agent_tools()
        for plugin_info in plugin_tools_info:
            plugin_id = plugin_info.get("plugin_id")
            plugin_name = plugin_info.get("plugin_name")
            tool_classes = plugin_info.get("tools", [])
            for ToolClass in tool_classes:
                try:
                    # 验证工具类是否继承自 MoviePilotTool
                    if not issubclass(ToolClass, MoviePilotTool):
                        logger.warning(f"插件 {plugin_name}({plugin_id}) 提供的工具类 {ToolClass.__name__} 未继承自 MoviePilotTool，已跳过")
                        continue
                    # 创建工具实例
                    tool = ToolClass(
                        session_id=session_id,
                        user_id=user_id
                    )
                    tool.set_message_attr(channel=channel, source=source, username=username)
                    tool.set_callback_handler(callback_handler=callback_handler)
                    tools.append(tool)
                    plugin_tools_count += 1
                    logger.debug(f"成功加载插件 {plugin_name}({plugin_id}) 的工具: {ToolClass.__name__}")
                except Exception as e:
                    logger.error(f"加载插件 {plugin_name}({plugin_id}) 的工具 {ToolClass.__name__} 失败: {str(e)}")
        
        builtin_tools_count = len(tool_definitions)
        if plugin_tools_count > 0:
            logger.info(f"成功创建 {len(tools)} 个MoviePilot工具（内置工具: {builtin_tools_count} 个，插件工具: {plugin_tools_count} 个）")
        else:
            logger.info(f"成功创建 {len(tools)} 个MoviePilot工具")
        return tools
