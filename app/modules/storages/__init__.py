"""存储后端。

每个存储是一个独立模块，与媒体服务器、下载器同级，按存储类型精确分发。
模块扫描只遍历 ``app.modules`` 的一级条目，具体存储类须在此处导出才能进入注册表。
"""
from typing import Optional

from app.modules.storages.base import StorageBase, transfer_process
from app.modules.storages.alipan import AliPan
from app.modules.storages.alist import Alist
from app.modules.storages.alistgo import AlistGo
from app.modules.storages.local import LocalStorage
from app.modules.storages.rclone import Rclone
from app.modules.storages.smb import SMB
from app.modules.storages.u115 import U115Pan

def get_storage(schema: str, capability: Optional[str] = None) -> Optional[StorageBase]:
    """
    按存储标识取运行中的存储模块

    供需要直接操作存储的模块使用。存储链只能按单一存储分发，跨存储的整理与需要连续多步
    存储操作的场景取不到合适的入口；模块回调存储链又会在一次分发的执行中重新进入分发。

    :param schema: 存储标识
    :param capability: 要求该存储实现的方法名，为空时不作要求
    :return: 存储模块实例，未运行或不具备该能力时为 None
    """
    if not schema:
        return None
    from app.runtime.extensions.module_manager import ModuleManager
    for module in ModuleManager().get_running_subtype_module(schema):
        if not capability or hasattr(module, capability):
            return module
    return None


def walk_files(storage: StorageBase, fileitem) -> list:
    """
    递归列出目录下的全部文件

    存储驱动只提供单层 list，递归属于编排，由调用方完成。

    :param storage: 存储模块实例
    :param fileitem: 目录项
    :return: 文件项列表，目录项不在其中
    """
    collected = []
    for child in storage.list(fileitem) or []:
        if child.type == "dir":
            collected.extend(walk_files(storage, child))
        else:
            collected.append(child)
    return collected


__all__ = [
    "AliPan",
    "Alist",
    "AlistGo",
    "LocalStorage",
    "Rclone",
    "SMB",
    "StorageBase",
    "get_storage",
    "U115Pan",
    "transfer_process",
]
