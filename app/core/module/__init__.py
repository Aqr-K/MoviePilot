# -*- coding: utf-8 -*-
"""
app.core.module 包：模块管理（manager）/ 动态加载（loader）/ 契约校验（contract）。

稳定公共 API（保持 from app.core.module import X 零改动；历史上为单文件 app/core/module.py）：
  - ModuleManager        模块管理器（注册/生命周期），见 .manager
  - ModuleType           模块类型枚举（再导出自 app.schemas.types）
  - verify_*_contract     契约校验家族（module/data_source/downloader/notification/mediaserver），见 .contract

公共名按需懒加载（PEP 562 __getattr__）。关键不变量：``import app.core.module.loader`` 不应触发
manager 的重依赖（config/event/singleton…）——动态加载工具 ModuleHelper 被 filemanager/indexer/
workflow 等在 import 期使用，必须可单独 import 而不拖入模块管理器依赖图（S3 解耦成果）。故此 __init__
不在模块顶层 import 任何子模块，仅在属性首次访问时按需解析。
"""
from typing import TYPE_CHECKING

__all__ = [
    "ModuleManager",
    "ModuleType",
    "verify_module_contract",
    "verify_data_source_contract",
    "verify_downloader_contract",
    "verify_notification_contract",
    "verify_mediaserver_contract",
]

# 公共名 → (子模块全名, 属性名)。延迟到首次属性访问时再 import，避免子模块（尤其 loader）
# 的 import 触发 manager 的重依赖链。
_LAZY_EXPORTS = {
    "ModuleManager": ("app.core.module.manager", "ModuleManager"),
    "ModuleType": ("app.schemas.types", "ModuleType"),
    "verify_module_contract": ("app.core.module.contract", "verify_module_contract"),
    "verify_data_source_contract": ("app.core.module.contract", "verify_data_source_contract"),
    "verify_downloader_contract": ("app.core.module.contract", "verify_downloader_contract"),
    "verify_notification_contract": ("app.core.module.contract", "verify_notification_contract"),
    "verify_mediaserver_contract": ("app.core.module.contract", "verify_mediaserver_contract"),
}


def __getattr__(name: str):
    """PEP 562 懒加载：仅当访问公共名时才 import 对应子模块并取出属性。"""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    return getattr(importlib.import_module(target[0]), target[1])


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


if TYPE_CHECKING:  # 仅供静态检查/IDE 解析；运行时一律走上面的懒加载
    from app.schemas.types import ModuleType
    from app.core.module.contract import (
        verify_data_source_contract,
        verify_downloader_contract,
        verify_mediaserver_contract,
        verify_module_contract,
        verify_notification_contract,
    )
    from app.core.module.manager import ModuleManager
