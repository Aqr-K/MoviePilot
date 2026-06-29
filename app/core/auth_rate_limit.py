"""认证端点的共享限流器。

``/access-token``、``/auth/flow/begin``、``/auth/flow/advance`` 三个未认证口令端点共用**同一**
滑窗限流器实例（10 次 / 60 秒），按 ``ip[:username]`` 计数。集中于此单一来源，避免各端点各自持有
独立实例导致同一 ``(ip, username)`` 的暴破预算被翻倍（如 access-token 与 flow 各 10 次 → 实际 20 次）。

进程级；多实例部署需换共享后端（如 Redis）。
"""
from app.utils.limit import KeyedWindowRateLimiter

# 认证端点共享限流器：10 次 / 60 秒 / (ip[:username])。
auth_rate_limiter = KeyedWindowRateLimiter(max_calls=10, window_seconds=60)
