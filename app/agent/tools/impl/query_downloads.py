"""查询下载工具"""

import json
from typing import Optional

from app.db.download_oper import DownloadOper
from app.log import logger
from app.agent.tools.base import MoviePilotTool


class QueryDownloadsTool(MoviePilotTool):
    name: str = "query_downloads"
    description: str = "查询下载状态，查看下载器的任务列表和进度。"

    async def _arun(self, explanation: str, downloader: Optional[str] = None, 
                    status: Optional[str] = "all") -> str:
        logger.info(f"执行工具: {self.name}, 参数: downloader={downloader}, status={status}")
        try:
            download_oper = DownloadOper()
            downloads = download_oper.list()
            filtered_downloads = []
            for dl in downloads:
                if downloader and dl.downloader != downloader:
                    continue
                if status != "all" and dl.status != status:
                    continue
                filtered_downloads.append(dl)
            if filtered_downloads:
                return json.dumps([d.dict() for d in filtered_downloads], ensure_ascii=False, indent=2)
            return "未找到相关下载任务。"
        except Exception as e:
            logger.error(f"查询下载失败: {e}")
            return f"查询下载时发生错误: {str(e)}"
