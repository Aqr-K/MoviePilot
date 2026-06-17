# 兼容垫片：Redis 客户端封装已迁移至 app.core.redis（缓存后端基础设施且依赖 settings，
# 不应位于 helper 层而被 core/cache 反向依赖）。此处保留 re-export 以兼容历史导入路径
# （含社区插件，如 p115strmhelper）。
from app.core.redis import (  # noqa: F401
    AsyncRedisHelper,
    RedisHelper,
    deserialize,
    serialize,
)

__all__ = ["RedisHelper", "AsyncRedisHelper", "serialize", "deserialize"]
