"""查询下载工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.download import DownloadChain
from app.log import logger


class QueryDownloadsInput(BaseModel):
    """查询下载工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    downloader: Optional[str] = Field(None,
                                      description="Name of specific downloader to query (optional, if not provided queries all configured downloaders)")
    status: Optional[str] = Field("all",
                                  description="Filter downloads by status: 'downloading' for active downloads, 'completed' for finished downloads, 'paused' for paused downloads, 'all' for all downloads")


class QueryDownloadsTool(MoviePilotTool):
    name: str = "query_downloads"
    description: str = "Query download status and list all active download tasks. Shows download progress, completion status, and task details from configured downloaders."
    args_schema: Type[BaseModel] = QueryDownloadsInput

    async def run(self, downloader: Optional[str] = None,
                  status: Optional[str] = "all", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: downloader={downloader}, status={status}")
        try:
            download_chain = DownloadChain()
            # 使用 DownloadChain.downloading 方法获取正在下载的任务
            downloads = download_chain.downloading(name=downloader)
            filtered_downloads = []
            for dl in downloads:
                if downloader and dl.downloader != downloader:
                    continue
                if status != "all" and dl.status != status:
                    continue
                filtered_downloads.append(dl)
            if filtered_downloads:
                return json.dumps([d.model_dump() for d in filtered_downloads])
            return "未找到相关下载任务。"
        except Exception as e:
            logger.error(f"查询下载失败: {e}", exc_info=True)
            return f"查询下载时发生错误: {str(e)}"
