"""添加下载工具"""

import re
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool, ToolChain
from app.chain.search import SearchChain
from app.chain.download import DownloadChain
from app.core.config import settings
from app.core.context import Context
from app.core.metainfo import MetaInfo
from app.db.site_oper import SiteOper
from app.log import logger
from app.schemas import TorrentInfo
from app.utils.crypto import HashUtils


class AddDownloadInput(BaseModel):
    """添加下载工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    torrent_url: str = Field(
        ...,
        description="torrent_url in hash:id format (can be obtained from search_torrents tool)"
    )
    downloader: Optional[str] = Field(None,
                                      description="Name of the downloader to use (optional, uses default if not specified)")
    save_path: Optional[str] = Field(None,
                                     description="Directory path where the downloaded files should be saved. Using `<storage>:<path>` for remote storage. e.g. rclone:/MP, smb:/server/share/Movies. (optional, uses default path if not specified)")
    labels: Optional[str] = Field(None,
                                  description="Comma-separated list of labels/tags to assign to the download (optional, e.g., 'movie,hd,bluray')")


class AddDownloadTool(MoviePilotTool):
    name: str = "add_download"
    description: str = "Add torrent download task to the configured downloader (qBittorrent, Transmission, etc.) using torrent_url reference from search_torrents results."
    args_schema: Type[BaseModel] = AddDownloadInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据下载参数生成友好的提示消息"""
        torrent_url = kwargs.get("torrent_url")
        downloader = kwargs.get("downloader")
        
        message = f"正在添加下载任务: 资源 {torrent_url}"
        if downloader:
            message += f" [下载器: {downloader}]"
        
        return message

    @staticmethod
    def _build_torrent_ref(context: Context) -> str:
        """生成用于校验缓存项的短引用"""
        if not context or not context.torrent_info:
            return ""
        return HashUtils.sha1(context.torrent_info.enclosure or "")[:7]

    @staticmethod
    def _is_torrent_ref(torrent_ref: Optional[str]) -> bool:
        """判断是否为内部搜索结果引用"""
        if not torrent_ref:
            return False
        return bool(re.fullmatch(r"[0-9a-f]{7}:\d+", str(torrent_ref).strip()))

    @classmethod
    def _resolve_cached_context(cls, torrent_ref: str) -> Optional[Context]:
        """从最近一次搜索缓存中解析种子上下文，仅支持 hash:id 格式"""
        ref = str(torrent_ref).strip()
        if ":" not in ref:
            return None
        try:
            ref_hash, ref_index = ref.split(":", 1)
            index = int(ref_index)
        except (TypeError, ValueError):
            return None

        if index < 1:
            return None

        results = SearchChain().last_search_results() or []
        if index > len(results):
            return None
        context = results[index - 1]
        if not ref_hash or cls._build_torrent_ref(context) != ref_hash:
            return None
        return context

    @staticmethod
    def _merge_labels_with_system_tag(labels: Optional[str]) -> Optional[str]:
        """合并用户标签与系统默认标签，确保任务可被系统管理"""
        system_tag = (settings.TORRENT_TAG or "").strip()
        user_labels = [item.strip() for item in (labels or "").split(",") if item.strip()]

        if system_tag and system_tag not in user_labels:
            user_labels.append(system_tag)

        return ",".join(user_labels) if user_labels else None

    async def run(self, torrent_url: Optional[str] = None,
                  downloader: Optional[str] = None, save_path: Optional[str] = None,
                  labels: Optional[str] = None, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: torrent_url={torrent_url}, downloader={downloader}, save_path={save_path}, labels={labels}")

        try:
            if not torrent_url or not self._is_torrent_ref(torrent_url):
                return "错误：torrent_url 必须是 search_torrents 返回的 hash:id 引用，请重新搜索后选择。"

            cached_context = self._resolve_cached_context(torrent_url)
            if not cached_context or not cached_context.torrent_info:
                return "错误：torrent_url 无效，请重新使用 search_torrents 搜索"

            cached_torrent = cached_context.torrent_info
            site_name = cached_torrent.site_name
            torrent_title = cached_torrent.title
            torrent_description = cached_torrent.description
            torrent_url = cached_torrent.enclosure

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
            media_info = cached_context.media_info if cached_context and cached_context.media_info else None
            if not media_info:
                media_info = await ToolChain().async_recognize_media(meta=meta_info)
            if not media_info:
                return "错误：无法识别媒体信息，无法添加下载任务"
            context = Context(
                torrent_info=torrent_info,
                meta_info=meta_info,
                media_info=media_info
            )

            merged_labels = self._merge_labels_with_system_tag(labels)

            did = download_chain.download_single(
                context=context,
                downloader=downloader,
                save_path=save_path,
                label=merged_labels
            )
            if did:
                return f"成功添加下载任务：{torrent_title}"
            else:
                return "添加下载任务失败"
        except Exception as e:
            logger.error(f"添加下载任务失败: {e}", exc_info=True)
            return f"添加下载任务时发生错误: {str(e)}"
