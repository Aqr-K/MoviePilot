"""schemas 层的本地化挂钩。

传输模型需要按当前请求语境翻译消息文本，但 schemas 不依赖任何运行时实现；
翻译函数由组合根在启动期注入，未注入时文本原样返回。
"""

from typing import Callable, Optional

Translator = Callable[[str], str]

_translator: Optional[Translator] = None


def configure_translator(translator: Optional[Translator]) -> None:
    """注册按当前请求语境翻译文本的实现，由组合根装配。"""
    global _translator
    _translator = translator


def translate(text: str) -> str:
    """按当前请求语境翻译文本；未注入实现时原样返回。"""
    if _translator is None:
        return text
    return _translator(text)
