"""修改下载任务工具"""

from typing import Optional, Type, List

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.download import DownloadChain
from app.log import logger


class ModifyDownloadInput(BaseModel):
    """修改下载任务工具的输入参数模型"""

    explanation: str = Field(
        ...,
        description="Clear explanation of why this tool is being used in the current context",
    )
    hash: str = Field(
        ..., description="Task hash (can be obtained from query_download_tasks tool)"
    )
    action: Optional[str] = Field(
        None,
        description="Action to perform on the task: 'start' to resume downloading, 'stop' to pause downloading. "
        "If not provided, no start/stop action will be performed.",
    )
    tags: Optional[List[str]] = Field(
        None,
        description="List of tags to set on the download task. If provided, these tags will be added to the task. "
        "Example: ['movie', 'hd']",
    )
    downloader: Optional[str] = Field(
        None,
        description="Name of specific downloader (optional, if not provided will search all downloaders)",
    )


class ModifyDownloadTool(MoviePilotTool):
    """修改下载任务工具"""

    name: str = "modify_download"
    description: str = (
        "Modify a download task in the downloader by task hash. "
        "Supports: 1) Setting tags on a download task, "
        "2) Starting (resuming) a paused download task, "
        "3) Stopping (pausing) a downloading task. "
        "Multiple operations can be performed in a single call."
    )
    args_schema: Type[BaseModel] = ModifyDownloadInput
    require_admin: bool = True

    def get_tool_message(self, **kwargs) -> Optional[str]:
        hash_value = kwargs.get("hash", "")
        action = kwargs.get("action")
        tags = kwargs.get("tags")
        downloader = kwargs.get("downloader")

        parts = [f"正在修改下载任务: {hash_value}"]
        if action == "start":
            parts.append("操作: 开始下载")
        elif action == "stop":
            parts.append("操作: 暂停下载")
        if tags:
            parts.append(f"标签: {', '.join(tags)}")
        if downloader:
            parts.append(f"下载器: {downloader}")
        return " | ".join(parts)

    async def run(
        self,
        hash: str,
        action: Optional[str] = None,
        tags: Optional[List[str]] = None,
        downloader: Optional[str] = None,
        **kwargs,
    ) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: hash={hash}, action={action}, tags={tags}, downloader={downloader}"
        )

        try:
            # 校验 hash 格式
            if len(hash) != 40 or not all(c in "0123456789abcdefABCDEF" for c in hash):
                return "参数错误：hash 格式无效，请先使用 query_download_tasks 工具获取正确的 hash。"

            # 校验参数：至少需要一个操作
            if not action and not tags:
                return "参数错误：至少需要指定 action（start/stop）或 tags 中的一个。"

            # 校验 action 参数
            if action and action not in ("start", "stop"):
                return f"参数错误：action 只支持 'start'（开始下载）或 'stop'（暂停下载），收到: '{action}'。"

            download_chain = DownloadChain()
            results = []

            # 设置标签
            if tags:
                tag_result = download_chain.set_torrents_tag(
                    hashs=[hash], tags=tags, downloader=downloader
                )
                if tag_result:
                    results.append(f"成功设置标签：{', '.join(tags)}")
                else:
                    results.append(f"设置标签失败，请检查任务是否存在或下载器是否可用")

            # 执行开始/暂停操作
            if action:
                action_result = download_chain.set_downloading(
                    hash_str=hash, oper=action, name=downloader
                )
                action_desc = "开始" if action == "start" else "暂停"
                if action_result:
                    results.append(f"成功{action_desc}下载任务")
                else:
                    results.append(
                        f"{action_desc}下载任务失败，请检查任务是否存在或下载器是否可用"
                    )

            return f"下载任务 {hash}：" + "；".join(results)

        except Exception as e:
            logger.error(f"修改下载任务失败: {e}", exc_info=True)
            return f"修改下载任务时发生错误: {str(e)}"
