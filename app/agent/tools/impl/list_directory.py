"""查询文件系统目录内容工具"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.storage import StorageChain
from app.log import logger
from app.schemas.file import FileItem
from app.utils.string import StringUtils


class ListDirectoryInput(BaseModel):
    """查询文件系统目录内容工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    path: str = Field(..., description="Directory path to list contents (e.g., '/home/user/downloads' or 'C:/Downloads')")
    storage: Optional[str] = Field("local", description="Storage type (default: 'local' for local file system, can be 'smb', 'alist', etc.)")
    sort_by: Optional[str] = Field("name", description="Sort order: 'name' for alphabetical sorting, 'time' for modification time sorting (default: 'name')")


class ListDirectoryTool(MoviePilotTool):
    name: str = "list_directory"
    description: str = "List actual files and folders in a file system directory (NOT configuration). Shows files and subdirectories with their names, types, sizes, and modification times. Returns up to 20 items and the total count if there are more items. Use 'query_directories' to query directory configuration settings."
    args_schema: Type[BaseModel] = ListDirectoryInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据目录参数生成友好的提示消息"""
        path = kwargs.get("path", "")
        storage = kwargs.get("storage", "local")
        
        message = f"正在查询目录: {path}"
        if storage != "local":
            message += f" [存储: {storage}]"
        
        return message

    async def run(self, path: str, storage: Optional[str] = "local",
                  sort_by: Optional[str] = "name", **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: path={path}, storage={storage}, sort_by={sort_by}")

        try:
            # 规范化路径
            if not path:
                return "错误：路径不能为空"
            
            # 确保路径格式正确
            if storage == "local":
                # 本地路径处理
                if not path.startswith("/") and not (len(path) > 1 and path[1] == ":"):
                    # 相对路径，尝试转换为绝对路径
                    path = str(Path(path).resolve())
            else:
                # 远程存储路径，确保以/开头
                if not path.startswith("/"):
                    path = "/" + path
            
            # 创建FileItem
            fileitem = FileItem(
                storage=storage or "local",
                path=path,
                type="dir"
            )
            
            # 查询目录内容
            storage_chain = StorageChain()
            file_list = storage_chain.list_files(fileitem, recursion=False)
            
            if file_list is None:
                return f"无法访问目录：{path}，请检查路径是否正确或存储是否可用"
            
            if not file_list:
                return f"目录 {path} 为空"
            
            # 排序
            if sort_by == "time":
                file_list.sort(key=lambda x: x.modify_time or 0, reverse=True)
            else:
                # 默认按名称排序（目录优先，然后按名称）
                file_list.sort(key=lambda x: (
                    0 if x.type == "dir" else 1,
                    StringUtils.natural_sort_key(x.name or "")
                ))
            
            # 限制返回数量
            total_count = len(file_list)
            limited_list = file_list[:20]
            
            # 转换为字典格式
            simplified_items = []
            for item in limited_list:
                # 格式化文件大小
                size_str = None
                if item.size:
                    size_str = StringUtils.str_filesize(item.size)
                
                # 格式化修改时间
                modify_time_str = None
                if item.modify_time:
                    try:
                        modify_time_str = datetime.fromtimestamp(item.modify_time).strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, OSError):
                        modify_time_str = str(item.modify_time)
                
                simplified = {
                    "name": item.name,
                    "type": item.type,
                    "path": item.path,
                    "size": size_str,
                    "modify_time": modify_time_str
                }
                # 如果是文件，添加扩展名
                if item.type == "file" and item.extension:
                    simplified["extension"] = item.extension
                simplified_items.append(simplified)
            
            result_json = json.dumps(simplified_items, ensure_ascii=False, indent=2)
            
            # 如果结果被裁剪，添加提示信息
            if total_count > 20:
                return f"注意：目录中共有 {total_count} 个项目，为节省上下文空间，仅显示前 20 个项目。\n\n{result_json}"
            else:
                return result_json
        except Exception as e:
            logger.error(f"查询目录内容失败: {e}", exc_info=True)
            return f"查询目录内容时发生错误: {str(e)}"

