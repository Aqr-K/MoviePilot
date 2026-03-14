"""查询系统目录设置工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.helper.directory import DirectoryHelper
from app.log import logger


class QueryDirectorySettingsInput(BaseModel):
    """查询系统目录设置工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    directory_type: Optional[str] = Field("all",
                                          description="Filter directories by type: 'download' for download directories, 'library' for media library directories, 'all' for all directories")
    storage_type: Optional[str] = Field("all",
                                        description="Filter directories by storage type: 'local' for local storage, 'remote' for remote storage, 'all' for all storage types")
    name: Optional[str] = Field(None,
                               description="Filter directories by name (partial match, optional)")


class QueryDirectorySettingsTool(MoviePilotTool):
    name: str = "query_directory_settings"
    description: str = "Query system directory configuration settings (NOT file listings). Returns configured directory paths, storage types, transfer modes, and other directory-related settings. Use 'list_directory' to list actual files and folders in a directory."
    args_schema: Type[BaseModel] = QueryDirectorySettingsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        directory_type = kwargs.get("directory_type", "all")
        storage_type = kwargs.get("storage_type", "all")
        name = kwargs.get("name")
        
        parts = ["正在查询目录配置"]
        
        if directory_type != "all":
            type_map = {"download": "下载目录", "library": "媒体库目录"}
            parts.append(f"类型: {type_map.get(directory_type, directory_type)}")
        
        if storage_type != "all":
            storage_map = {"local": "本地存储", "remote": "远程存储"}
            parts.append(f"存储: {storage_map.get(storage_type, storage_type)}")
        
        if name:
            parts.append(f"名称: {name}")
        
        return " | ".join(parts) if len(parts) > 1 else parts[0]

    async def run(self, directory_type: Optional[str] = "all",
                  storage_type: Optional[str] = "all",
                  name: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: directory_type={directory_type}, storage_type={storage_type}, name={name}")

        try:
            directory_helper = DirectoryHelper()
            
            # 根据目录类型获取目录列表
            if directory_type == "download":
                dirs = directory_helper.get_download_dirs()
            elif directory_type == "library":
                dirs = directory_helper.get_library_dirs()
            else:
                dirs = directory_helper.get_dirs()
            
            # 按存储类型过滤
            filtered_dirs = []
            for d in dirs:
                # 按存储类型过滤
                if storage_type == "local":
                    # 对于下载目录，检查 storage；对于媒体库目录，检查 library_storage
                    if directory_type == "download" and d.storage != "local":
                        continue
                    elif directory_type == "library" and d.library_storage != "local":
                        continue
                    elif directory_type == "all":
                        # 检查是否有本地存储配置
                        if d.download_path and d.storage != "local":
                            continue
                        if d.library_path and d.library_storage != "local":
                            continue
                elif storage_type == "remote":
                    # 对于下载目录，检查 storage；对于媒体库目录，检查 library_storage
                    if directory_type == "download" and d.storage == "local":
                        continue
                    elif directory_type == "library" and d.library_storage == "local":
                        continue
                    elif directory_type == "all":
                        # 检查是否有远程存储配置
                        if d.download_path and d.storage == "local":
                            continue
                        if d.library_path and d.library_storage == "local":
                            continue
                
                # 按名称过滤（部分匹配）
                if name and d.name and name.lower() not in d.name.lower():
                    continue
                
                filtered_dirs.append(d)
            
            if filtered_dirs:
                # 转换为字典格式，只保留关键信息
                simplified_dirs = []
                for d in filtered_dirs:
                    simplified = {
                        "name": d.name,
                        "priority": d.priority,
                        "storage": d.storage,
                        "download_path": d.download_path,
                        "library_path": d.library_path,
                        "library_storage": d.library_storage,
                        "media_type": d.media_type,
                        "media_category": d.media_category,
                        "monitor_type": d.monitor_type,
                        "monitor_mode": d.monitor_mode,
                        "transfer_type": d.transfer_type,
                        "overwrite_mode": d.overwrite_mode,
                        "renaming": d.renaming,
                        "scraping": d.scraping,
                        "notify": d.notify,
                        "download_type_folder": d.download_type_folder,
                        "download_category_folder": d.download_category_folder,
                        "library_type_folder": d.library_type_folder,
                        "library_category_folder": d.library_category_folder
                    }
                    simplified_dirs.append(simplified)
                
                result_json = json.dumps(simplified_dirs, ensure_ascii=False, indent=2)
                return result_json
            return "未找到相关目录配置"
        except Exception as e:
            logger.error(f"查询系统目录设置失败: {e}", exc_info=True)
            return f"查询系统目录设置时发生错误: {str(e)}"

