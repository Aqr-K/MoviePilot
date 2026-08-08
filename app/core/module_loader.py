# -*- coding: utf-8 -*-
"""
兼容垫片：模块动态加载工具已随 module 包化迁移至 app.core.module.loader。

历史导入路径 app.core.module_loader 保持零改动可用——本垫片与新路径解析到同一批对象
（ModuleHelper / FilterFuncType / _default_filter）。新代码请直接 import app.core.module.loader。

本垫片仅依赖标准库与新 loader 模块，不引入任何上层依赖，保持 core 层动态加载工具的轻量独立。
"""
from app.core.module.loader import FilterFuncType, ModuleHelper, _default_filter  # noqa: F401

__all__ = ["ModuleHelper", "FilterFuncType"]
