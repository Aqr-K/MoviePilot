"""删除下载任务工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.download import DownloadChain
from app.log import logger


class DeleteDownloadInput(BaseModel):
    """删除下载任务工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )
    hash: str = Field(
        ..., description="Task hash (can be obtained from query_download_tasks tool)"
    )
    downloader: Optional[str] = Field(
        None,
        description="Name of specific downloader (optional, if not provided will search all downloaders)",
    )
    delete_files: Optional[bool] = Field(
        False,
        description="Whether to delete downloaded files along with the task (default: False, only removes the task from downloader)",
    )


class DeleteDownloadTool(MoviePilotTool):
    name: str = "delete_download"
    description: str = "Delete a download task from the downloader by task hash only. Optionally specify the downloader name and whether to delete downloaded files."
    args_schema: Type[BaseModel] = DeleteDownloadInput
    require_admin: bool = True

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据删除参数生成友好的提示消息"""
        hash_value = kwargs.get("hash", "")
        downloader = kwargs.get("downloader")
        delete_files = kwargs.get("delete_files", False)

        message = f"正在删除下载任务: {hash_value}"
        if downloader:
            message += f" [下载器: {downloader}]"
        if delete_files:
            message += " (包含文件)"

        return message

    async def run(
        self,
        hash: str,
        downloader: Optional[str] = None,
        delete_files: Optional[bool] = False,
        **kwargs,
    ) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: hash={hash}, downloader={downloader}, delete_files={delete_files}"
        )

        try:
            download_chain = DownloadChain()

            # 仅支持通过hash删除任务
            if len(hash) != 40 or not all(c in "0123456789abcdefABCDEF" for c in hash):
                return "参数错误：hash 格式无效，请先使用 query_download_tasks 工具获取正确的 hash。"

            # 删除下载任务
            # remove_torrents 支持 delete_file 参数，可以控制是否删除文件
            result = download_chain.remove_torrents(
                hashs=[hash], downloader=downloader, delete_file=delete_files
            )

            if result:
                files_info = "（包含文件）" if delete_files else "（不包含文件）"
                return f"成功删除下载任务：{hash} {files_info}"
            else:
                return f"删除下载任务失败：{hash}，请检查任务是否存在或下载器是否可用"
        except Exception as e:
            logger.error(f"删除下载任务失败: {e}", exc_info=True)
            return f"删除下载任务时发生错误: {str(e)}"
