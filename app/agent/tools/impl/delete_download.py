"""删除下载任务工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.download import DownloadChain
from app.log import logger


class DeleteDownloadInput(BaseModel):
    """删除下载任务工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    task_identifier: str = Field(..., description="Task identifier: can be task hash (unique identifier) or task title/name")
    downloader: Optional[str] = Field(None, description="Name of specific downloader (optional, if not provided will search all downloaders)")
    delete_files: Optional[bool] = Field(False, description="Whether to delete downloaded files along with the task (default: False, only removes the task from downloader)")


class DeleteDownloadTool(MoviePilotTool):
    name: str = "delete_download"
    description: str = "Delete a download task from the downloader. Can delete by task hash (unique identifier) or task title/name. Optionally specify the downloader name and whether to delete downloaded files."
    args_schema: Type[BaseModel] = DeleteDownloadInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据删除参数生成友好的提示消息"""
        task_identifier = kwargs.get("task_identifier", "")
        downloader = kwargs.get("downloader")
        delete_files = kwargs.get("delete_files", False)
        
        message = f"正在删除下载任务: {task_identifier}"
        if downloader:
            message += f" [下载器: {downloader}]"
        if delete_files:
            message += " (包含文件)"
        
        return message

    async def run(self, task_identifier: str, downloader: Optional[str] = None,
                  delete_files: Optional[bool] = False, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: task_identifier={task_identifier}, downloader={downloader}, delete_files={delete_files}")

        try:
            download_chain = DownloadChain()
            
            # 如果task_identifier看起来像hash（通常是40个字符的十六进制字符串）
            task_hash = None
            if len(task_identifier) == 40 and all(c in '0123456789abcdefABCDEF' for c in task_identifier):
                # 直接使用hash
                task_hash = task_identifier
            else:
                # 通过标题查找任务
                downloads = download_chain.downloading(name=downloader)
                for dl in downloads:
                    # 检查标题或名称是否匹配
                    if (task_identifier.lower() in (dl.title or "").lower()) or \
                       (task_identifier.lower() in (dl.name or "").lower()):
                        task_hash = dl.hash
                        break
                
                if not task_hash:
                    return f"未找到匹配的下载任务：{task_identifier}，请使用 query_downloads 工具查询可用的下载任务"
            
            # 删除下载任务
            # remove_torrents 支持 delete_file 参数，可以控制是否删除文件
            result = download_chain.remove_torrents(hashs=[task_hash], downloader=downloader, delete_file=delete_files)
            
            if result:
                files_info = "（包含文件）" if delete_files else "（不包含文件）"
                return f"成功删除下载任务：{task_identifier} {files_info}"
            else:
                return f"删除下载任务失败：{task_identifier}，请检查任务是否存在或下载器是否可用"
        except Exception as e:
            logger.error(f"删除下载任务失败: {e}", exc_info=True)
            return f"删除下载任务时发生错误: {str(e)}"

