from typing import Optional, List

from app import schemas
from app.chain import ChainBase


class DashboardChain(ChainBase):
    """
    各类仪表板统计处理链
    """
    def media_statistic(self, server: Optional[str] = None) -> Optional[List[schemas.Statistic]]:
        """
        媒体数量统计
        """
        statistics = [
            statistic
            for group in self.multicast("media_statistic", server=server)
            for statistic in group
        ]
        return statistics or None

    def downloader_info(self, downloader: Optional[str] = None) -> Optional[List[schemas.DownloaderInfo]]:
        """
        下载器信息
        """
        infos = [
            info
            for group in self.multicast("downloader_info", downloader=downloader)
            for info in group
        ]
        return infos or None
