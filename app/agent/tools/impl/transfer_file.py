"""整理文件或目录工具"""

from pathlib import Path
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.transfer import TransferChain
from app.log import logger
from app.schemas import FileItem, MediaType


class TransferFileInput(BaseModel):
    """整理文件或目录工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    file_path: str = Field(..., description="Path to the file or directory to transfer (e.g., '/path/to/file.mkv' or '/path/to/directory')")
    storage: Optional[str] = Field("local", description="Storage type of the source file (default: 'local', can be 'smb', 'alist', etc.)")
    target_path: Optional[str] = Field(None, description="Target path for the transferred file/directory (optional, uses default library path if not specified)")
    target_storage: Optional[str] = Field(None, description="Target storage type (optional, uses default storage if not specified)")
    media_type: Optional[str] = Field(None, description="Media type: '电影' for films, '电视剧' for television series (optional, will be auto-detected if not specified)")
    tmdbid: Optional[int] = Field(None, description="TMDB ID for precise media identification (optional but recommended for accuracy)")
    doubanid: Optional[str] = Field(None, description="Douban ID for media identification (optional)")
    season: Optional[int] = Field(None, description="Season number for TV shows (optional)")
    transfer_type: Optional[str] = Field(None, description="Transfer mode: 'move' to move files, 'copy' to copy files, 'link' for hard link, 'softlink' for symbolic link (optional, uses default mode if not specified)")
    background: Optional[bool] = Field(False, description="Whether to run transfer in background (default: False, runs synchronously)")


class TransferFileTool(MoviePilotTool):
    name: str = "transfer_file"
    description: str = "Transfer/organize a file or directory to the media library. Automatically recognizes media information and organizes files according to configured rules. Supports custom target paths, media identification, and transfer modes."
    args_schema: Type[BaseModel] = TransferFileInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据整理参数生成友好的提示消息"""
        file_path = kwargs.get("file_path", "")
        media_type = kwargs.get("media_type")
        transfer_type = kwargs.get("transfer_type")
        background = kwargs.get("background", False)
        
        message = f"正在整理文件: {file_path}"
        if media_type:
            message += f" [{media_type}]"
        if transfer_type:
            transfer_map = {"move": "移动", "copy": "复制", "link": "硬链接", "softlink": "软链接"}
            message += f" 模式: {transfer_map.get(transfer_type, transfer_type)}"
        if background:
            message += " [后台运行]"
        
        return message

    async def run(self, file_path: str, storage: Optional[str] = "local",
                  target_path: Optional[str] = None,
                  target_storage: Optional[str] = None,
                  media_type: Optional[str] = None,
                  tmdbid: Optional[int] = None,
                  doubanid: Optional[str] = None,
                  season: Optional[int] = None,
                  transfer_type: Optional[str] = None,
                  background: Optional[bool] = False, **kwargs) -> str:
        logger.info(
            f"执行工具: {self.name}, 参数: file_path={file_path}, storage={storage}, target_path={target_path}, "
            f"target_storage={target_storage}, media_type={media_type}, tmdbid={tmdbid}, doubanid={doubanid}, "
            f"season={season}, transfer_type={transfer_type}, background={background}")

        try:
            if not file_path:
                return "错误：必须提供文件或目录路径"
            
            # 规范化路径
            if storage == "local":
                # 本地路径处理
                if not file_path.startswith("/") and not (len(file_path) > 1 and file_path[1] == ":"):
                    # 相对路径，尝试转换为绝对路径
                    file_path = str(Path(file_path).resolve())
            else:
                # 远程存储路径，确保以/开头
                if not file_path.startswith("/"):
                    file_path = "/" + file_path
            
            # 创建FileItem
            fileitem = FileItem(
                storage=storage or "local",
                path=file_path,
                type="dir" if file_path.endswith("/") else "file"
            )
            
            # 处理目标路径
            target_path_obj = None
            if target_path:
                target_path_obj = Path(target_path)
            
            # 处理媒体类型
            mtype = None
            if media_type:
                try:
                    mtype = MediaType(media_type)
                except ValueError:
                    return f"错误：无效的媒体类型 '{media_type}'，支持的类型：'movie', 'tv'"
            
            # 调用整理方法
            transfer_chain = TransferChain()
            state, errormsg = transfer_chain.manual_transfer(
                fileitem=fileitem,
                target_storage=target_storage,
                target_path=target_path_obj,
                tmdbid=tmdbid,
                doubanid=doubanid,
                mtype=mtype,
                season=season,
                transfer_type=transfer_type,
                background=background
            )
            
            if not state:
                # 处理错误信息
                if isinstance(errormsg, list):
                    error_text = f"整理完成，{len(errormsg)} 个文件转移失败"
                    if errormsg:
                        error_text += f"：\n" + "\n".join(str(e) for e in errormsg[:5])  # 只显示前5个错误
                        if len(errormsg) > 5:
                            error_text += f"\n... 还有 {len(errormsg) - 5} 个错误"
                else:
                    error_text = str(errormsg)
                return f"整理失败：{error_text}"
            else:
                if background:
                    return f"整理任务已提交到后台运行：{file_path}"
                else:
                    return f"整理成功：{file_path}"
        except Exception as e:
            logger.error(f"整理文件失败: {e}", exc_info=True)
            return f"整理文件时发生错误: {str(e)}"

