# 兼容垫片：ThreadHelper 已迁移至 app.core.thread（线程池属核心基础设施且依赖 settings，
# 不应位于 helper 层而被 core 反向依赖）。此处保留 re-export 以兼容历史导入路径。
from app.core.thread import ThreadHelper

__all__ = ["ThreadHelper"]
