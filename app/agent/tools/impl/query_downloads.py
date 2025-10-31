"""查询下载工具"""

import json
from typing import Optional

from app.chain.download import DownloadChain
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class QueryDownloadsTool(MoviePilotTool):
    name: str = "query_downloads"
    description: str = "查询下载状态，查看下载器的任务列表和进度。"

    async def _arun(self, explanation: str, downloader: Optional[str] = None, 
                    status: Optional[str] = "all") -> str:
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
                return json.dumps([d.dict() if hasattr(d, 'dict') else d.model_dump() if hasattr(d, 'model_dump') else d for d in filtered_downloads], ensure_ascii=False, indent=2)
            return "未找到相关下载任务。"
        except Exception as e:
            logger.error(f"查询下载失败: {e}", exc_info=True)
            return f"查询下载时发生错误: {str(e)}"
