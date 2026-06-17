# -*- coding: utf-8 -*-
"""
兼容垫片：ModuleHelper 已迁移至 app.core.module_loader。

ModuleHelper 是一个仅依赖标准库与 app.log 的动态模块加载工具，原先错误地放在
helper 层（helper 层依赖 core/db/modules），导致 core.module -> helper.module 的反向依赖。
现已迁移到正确的 core 层。此文件保留为 re-export 垫片，使既有导入路径
（含插件 app.plugins.autosignin）无需改动即可继续工作。
"""
from app.core.module_loader import FilterFuncType, ModuleHelper  # noqa: F401

__all__ = ["ModuleHelper", "FilterFuncType"]
