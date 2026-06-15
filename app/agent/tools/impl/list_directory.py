"""查询文件系统目录内容工具"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.agent.tools.tags import ToolTag
from app.chain.storage import StorageChain
from app.log import logger
from app.schemas.file import FileItem
from app.utils.string import StringUtils


class ListDirectoryInput(BaseModel):
    """查询文件系统目录内容工具的输入参数模型"""
    explanation: Optional[str] = Field(None, description="Clear explanation of why this tool is being used in the current context")
    path: str = Field(..., description="Directory path to list contents (e.g., '/home/user/downloads' or 'C:/Downloads')")
    storage: Optional[str] = Field("local", description="Storage type (default: 'local' for local file system, can be 'smb', 'alist', etc.)")
    sort_by: Optional[str] = Field("name", description="Sort order: 'name' for alphabetical sorting, 'time' for modification time sorting (default: 'name')")


class ListDirectoryTool(MoviePilotTool):
    name: str = "list_directory"
    tags: list[str] = [
        ToolTag.Read,
        ToolTag.Directory,
        ToolTag.File,
    ]
    description: str = "List actual files and folders in a file system directory (NOT configuration). Shows files and subdirectories with their names, types, sizes, and modification times. Returns up to 20 items and the total count if there are more items. Use 'query_directory_settings' to query directory configuration settings."
    args_schema: Type[BaseModel] = ListDirectoryInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据目录参数生成友好的提示消息"""
        path = kwargs.get("path", "")
        storage = kwargs.get("storage", "local")
        
        message = f"查询目录: {path}"
        if storage != "local":
            message += f" [存储: {storage}]"
        
        return message

    @staticmethod
    def _list_directory_sync(
        path: str, storage: Optional[str] = "local", sort_by: Optional[str] = "name"
    ) -> str:
        """
        目录遍历可能触发本地磁盘或远程存储请求，统一放到线程池中执行。
        """
        if not path:
            return "错误：路径不能为空"

        if storage == "local":
            if not path.startswith("/") and not (len(path) > 1 and path[1] == ":"):
                path = str(Path(path).resolve())
        elif not path.startswith("/"):
            path = "/" + path

        fileitem = FileItem(storage=storage or "local", path=path, type="dir")
        file_list = StorageChain().list_files(fileitem, recursion=False)

        if file_list is None:
            return f"无法访问目录：{path}，请检查路径是否正确或存储是否可用"
        if not file_list:
            return f"目录 {path} 为空"

        if sort_by == "time":
            file_list.sort(key=lambda x: x.modify_time or 0, reverse=True)
        else:
            file_list.sort(
                key=lambda x: (
                    0 if x.type == "dir" else 1,
                    StringUtils.natural_sort_key(x.name or ""),
                )
            )

        total_count = len(file_list)
        limited_list = file_list[:20]
        simplified_items = []
        for item in limited_list:
            size_str = StringUtils.str_filesize(item.size) if item.size else None
            modify_time_str = None
            if item.modify_time:
                try:
                    modify_time_str = datetime.fromtimestamp(item.modify_time).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except (ValueError, OSError):
                    modify_time_str = str(item.modify_time)

            simplified = {
                "name": item.name,
                "type": item.type,
                "path": item.path,
                "size": size_str,
                "modify_time": modify_time_str,
            }
            if item.type == "file" and item.extension:
                simplified["extension"] = item.extension
            simplified_items.append(simplified)

        result_json = json.dumps(simplified_items, ensure_ascii=False, indent=2)
        if total_count > 20:
            return (
                f"注意：目录中共有 {total_count} 个项目，为节省上下文空间，仅显示前 20 个项目。\n\n"
                f"{result_json}"
            )
        return result_json

    async def run(self, path: str, storage: Optional[str] = "local",
                  sort_by: Optional[str] = "name", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: path={path}, storage={storage}, sort_by={sort_by}")

        try:
            resolved_path, access_error = await self._check_local_storage_access(
                path=path, storage=storage, operation="列出"
            )
            if access_error:
                return access_error
            if resolved_path:
                path = str(resolved_path)
            return await self.run_blocking(
                "storage", self._list_directory_sync, path, storage, sort_by
            )
        except Exception as e:
            logger.error(f"查询目录内容失败: {e}", exc_info=True)
            return f"查询目录内容时发生错误: {str(e)}"
