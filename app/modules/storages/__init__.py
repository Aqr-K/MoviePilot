"""存储后端。

每个存储是一个独立模块，与媒体服务器、下载器同级，按存储类型精确分发。
模块扫描只遍历 ``app.modules`` 的一级条目，具体存储类须在此处导出才能进入注册表。
"""
from app.modules.storages.base import StorageBase, transfer_process
from app.modules.storages.alipan import AliPan
from app.modules.storages.alist import Alist
from app.modules.storages.alistgo import AlistGo
from app.modules.storages.local import LocalStorage
from app.modules.storages.rclone import Rclone
from app.modules.storages.smb import SMB
from app.modules.storages.u115 import U115Pan

__all__ = [
    "AliPan",
    "Alist",
    "AlistGo",
    "LocalStorage",
    "Rclone",
    "SMB",
    "StorageBase",
    "U115Pan",
    "transfer_process",
]
