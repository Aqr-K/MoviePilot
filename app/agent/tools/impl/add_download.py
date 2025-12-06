"""添加下载工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool, ToolChain
from app.chain.download import DownloadChain
from app.core.context import Context
from app.core.metainfo import MetaInfo
from app.db.site_oper import SiteOper
from app.log import logger
from app.schemas import TorrentInfo


class AddDownloadInput(BaseModel):
    """添加下载工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    site_name: str = Field(..., description="Name of the torrent site/source (e.g., 'The Pirate Bay')")
    torrent_title: str = Field(...,
                               description="The display name/title of the torrent (e.g., 'The.Matrix.1999.1080p.BluRay.x264')")
    torrent_url: str = Field(..., description="Direct URL to the torrent file (.torrent) or magnet link")
    torrent_description: Optional[str] = Field(None,
                                                  description="Brief description of the torrent content (optional)")
    downloader: Optional[str] = Field(None,
                                      description="Name of the downloader to use (optional, uses default if not specified)")
    save_path: Optional[str] = Field(None,
                                     description="Directory path where the downloaded files should be saved. Using `<storage>:<path>` for remote storage. e.g. rclone:/MP, smb:/server/share/Movies. (optional, uses default path if not specified)")
    labels: Optional[str] = Field(None,
                                  description="Comma-separated list of labels/tags to assign to the download (optional, e.g., 'movie,hd,bluray')")


class AddDownloadTool(MoviePilotTool):
    name: str = "add_download"
    description: str = "Add torrent download task to the configured downloader (qBittorrent, Transmission, etc.). Downloads the torrent file and starts the download process with specified settings."
    args_schema: Type[BaseModel] = AddDownloadInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据下载参数生成友好的提示消息"""
        torrent_title = kwargs.get("torrent_title", "")
        site_name = kwargs.get("site_name", "")
        downloader = kwargs.get("downloader")
        
        message = f"正在添加下载任务: {torrent_title}"
        if site_name:
            message += f" (来源: {site_name})"
        if downloader:
            message += f" [下载器: {downloader}]"
        
        return message

    async def run(self, site_name: str, torrent_title: str, torrent_url: str, torrent_description: Optional[str] = None,
                  downloader: Optional[str] = None, save_path: Optional[str] = None,
                  labels: Optional[str] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: site_name={site_name}, torrent_title={torrent_title}, torrent_url={torrent_url}, downloader={downloader}, save_path={save_path}, labels={labels}")

        try:
            if not torrent_title or not torrent_url:
                return "错误：必须提供种子标题和下载链接"

            # 使用DownloadChain添加下载
            download_chain = DownloadChain()

            # 根据站点名称查询站点cookie
            if not site_name:
                return "错误：必须提供站点名称，请从搜索资源结果信息中获取"
            siteinfo = await SiteOper().async_get_by_name(site_name)
            if not siteinfo:
                return f"错误：未找到站点信息：{site_name}"

            # 创建下载上下文
            torrent_info = TorrentInfo(
                title=torrent_title,
                description=torrent_description,
                enclosure=torrent_url,
                site_name=site_name,
                site_ua=siteinfo.ua,
                site_cookie=siteinfo.cookie,
                site_proxy=siteinfo.proxy,
                site_order=siteinfo.pri,
                site_downloader=siteinfo.downloader
            )
            meta_info = MetaInfo(title=torrent_title, subtitle=torrent_description)
            media_info = await ToolChain().async_recognize_media(meta=meta_info)
            if not media_info:
                return "错误：无法识别媒体信息，无法添加下载任务"
            context = Context(
                torrent_info=torrent_info,
                meta_info=meta_info,
                media_info=media_info
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
