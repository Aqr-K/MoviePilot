"""添加下载工具"""

from typing import Optional

from app.chain.download import DownloadChain
from app.core.context import Context
from app.core.metainfo import MetaInfo
from app.log import logger
from app.schemas import TorrentInfo
from app.agent.tools.base import MoviePilotTool


class AddDownloadTool(MoviePilotTool):
    name: str = "add_download"
    description: str = "添加下载任务，将搜索到的种子资源添加到下载器。"

    async def _arun(self, torrent_title: str, torrent_url: str, explanation: str, 
                    downloader: Optional[str] = None, save_path: Optional[str] = None, 
                    labels: Optional[str] = None) -> str:
        logger.info(f"执行工具: {self.name}, 参数: torrent_title={torrent_title}, torrent_url={torrent_url}, downloader={downloader}, save_path={save_path}, labels={labels}")
        
        # 发送工具执行说明
        self._send_tool_message(f"正在添加下载任务: {torrent_title}", "info")
        
        try:
            if not torrent_title or not torrent_url:
                error_message = "错误：必须提供种子标题和下载链接"
                self._send_tool_message(error_message, "error")
                return error_message

            # 使用DownloadChain添加下载
            download_chain = DownloadChain()
            
            # 创建下载上下文
            torrent_info = TorrentInfo(
                title=torrent_title,
                download_url=torrent_url
            )
            meta_info = MetaInfo(title=torrent_title)
            context = Context(
                torrent_info=torrent_info,
                meta_info=meta_info
            )

            did = download_chain.download_single(context=context, downloader=downloader, 
                                               save_path=save_path, label=labels)
            if did:
                success_message = f"成功添加下载任务：{torrent_title}"
                self._send_tool_message(success_message, "success")
                return success_message
            else:
                error_message = "添加下载任务失败"
                self._send_tool_message(error_message, "error")
                return error_message
        except Exception as e:
            error_message = f"添加下载任务时发生错误: {str(e)}"
            self._send_tool_message(error_message, "error")
            return error_message
