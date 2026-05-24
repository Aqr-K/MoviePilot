from typing import Any

from pywebpush import WebPushException


def is_webpush_subscription_gone(error: WebPushException) -> bool:
    """
    判断 WebPush 订阅是否已经在浏览器或推送服务侧失效。
    """
    response: Any = getattr(error, "response", None)
    status_code = getattr(response, "status_code", None) or getattr(response, "status", None)
    return status_code in {404, 410}
