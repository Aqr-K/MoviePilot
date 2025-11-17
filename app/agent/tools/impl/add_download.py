"""添加下载工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.download import DownloadChain
from app.core.context import Context
from app.core.metainfo import MetaInfo
from app.log import logger
from app.schemas import TorrentInfo


class AddDownloadInput(BaseModel):
    """添加下载工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    torrent_title: str = Field(...,
                               description="The display name/title of the torrent (e.g., 'The.Matrix.1999.1080p.BluRay.x264')")
    torrent_url: str = Field(..., description="Direct URL to the torrent file (.torrent) or magnet link")
    downloader: Optional[str] = Field(None,
                                      description="Name of the downloader to use (optional, uses default if not specified)")
    save_path: Optional[str] = Field(None,
                                     description="Directory path where the downloaded files should be saved (optional, uses default path if not specified)")
    labels: Optional[str] = Field(None,
                                  description="Comma-separated list of labels/tags to assign to the download (optional, e.g., 'movie,hd,bluray')")


class AddDownloadTool(MoviePilotTool):
    name: str = "add_download"
    description: str = "Add torrent download task to the configured downloader (qBittorrent, Transmission, etc.). Downloads the torrent file and starts the download process with specified settings."
    args_schema: Type[BaseModel] = AddDownloadInput

    async def run(self, torrent_title: str, torrent_url: str,
                  downloader: Optional[str] = None, save_path: Optional[str] = None,
                  labels: Optional[str] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: torrent_title={torrent_title}, torrent_url={torrent_url}, downloader={downloader}, save_path={save_path}, labels={labels}")

        try:
            if not torrent_title or not torrent_url:
                return "错误：必须提供种子标题和下载链接"

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

            did = download_chain.download_single(
                context=context,
                downloader=downloader,
                save_path=save_path,
                label=labels
            )
            if did:
                return f"成功添加下载任务：{torrent_title}"
            else:
                return "添加下载任务失败"
        except Exception as e:
            logger.error(f"添加下载任务失败: {e}", exc_info=True)
            return f"添加下载任务时发生错误: {str(e)}"
