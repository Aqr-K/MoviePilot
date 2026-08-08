"""
存储端点的 Chain 编排（service layer）。

把目录列举（StorageChain 取数 + 通配符过滤 + 排序）与递归智能重命名
（StorageChain 列举 + MediaChain 识别 + TransferChain 推荐命名 + 逐个重命名 + 进度）
从端点下沉到服务层：端点退化为薄 HTTP 适配层、不再 import
MediaChain/TransferChain/ProgressHelper 等；本层可通过 mock Chain 单测。
"""
import fnmatch
import math
import re
from pathlib import Path
from typing import List, Optional, Tuple

from app import schemas
from app.chain.media import MediaChain
from app.chain.storage import StorageChain
from app.chain.transfer import TransferChain
from app.core.config import settings
from app.helper.progress import ProgressHelper
from app.schemas.types import ProgressKey
from app.utils.string import StringUtils


def list_directory(
    fileitem: schemas.FileItem,
    sort: Optional[str] = "updated_at",
    keyword: Optional[str] = None,
) -> List[schemas.FileItem]:
    """
    列出目录下所有目录和文件：按 keyword 通配符（* ?）过滤，并按 name/时间排序。
    """
    file_list = StorageChain().list_files(fileitem)
    if file_list:
        if keyword:
            _pat = re.compile(fnmatch.translate(keyword), re.IGNORECASE)
            file_list = [f for f in file_list if _pat.match(f.name or "")]
        if sort == "name":
            file_list.sort(key=lambda x: StringUtils.natural_sort_key(x.name or ""))
        else:
            file_list.sort(key=lambda x: x.modify_time or -math.inf, reverse=True)
    return file_list


def batch_recursive_rename(fileitem: schemas.FileItem) -> Tuple[bool, str]:
    """
    递归修改目录内媒体文件（智能识别命名）。返回 (success, message)；
    success=False 时 message 为失败原因。
    """
    transferchain = TransferChain()
    media_exts = settings.RMT_MEDIAEXT + settings.RMT_SUBEXT + settings.RMT_AUDIOEXT
    sub_files: List[schemas.FileItem] = StorageChain().list_files(fileitem)
    if sub_files:
        # 开始进度
        progress = ProgressHelper(ProgressKey.BatchRename)
        progress.start()
        total = len(sub_files)
        handled = 0
        for sub_file in sub_files:
            handled += 1
            progress.update(
                value=handled / total * 100, text=f"正在处理 {sub_file.name} ..."
            )
            if sub_file.type == "dir":
                continue
            if not sub_file.extension:
                continue
            if f".{sub_file.extension.lower()}" not in media_exts:
                continue
            sub_path = Path(f"{fileitem.path}{sub_file.name}")
            context = MediaChain().recognize_by_path(
                sub_path,
                obtain_images=False,
            )
            if not context or not context.media_info:
                progress.end()
                return False, f"{sub_path.name} 未识别到媒体信息"
            new_path = transferchain.recommend_name(
                meta=context.meta_info, mediainfo=context.media_info
            )
            if not new_path:
                progress.end()
                return False, f"{sub_path.name} 未识别到新名称"
            result = StorageChain().rename_file(sub_file, Path(new_path).name)
            if not result:
                progress.end()
                return False, f"{sub_path.name} 重命名失败！"
        progress.end()
    return True, ""
