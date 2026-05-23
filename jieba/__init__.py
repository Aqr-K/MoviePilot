"""jieba 兼容入口。"""

from collections.abc import Iterator
from typing import Any

import jieba_next as _jieba_next
from jieba_next import cut_for_search as _cut_for_search
from jieba_next import lcut as _lcut
from jieba_next import lcut_for_search as _lcut_for_search


def cut(sentence: str, cut_all: bool = False, HMM: bool = True, use_paddle: bool = False) -> Iterator[str]:
    """
    兼容旧 jieba.cut 入口，底层委托给 jieba-next 的 Rust 加速实现。
    """
    return _jieba_next.cut(sentence, cut_all=cut_all, HMM=HMM)


def lcut(sentence: str, cut_all: bool = False, HMM: bool = True, use_paddle: bool = False) -> list[str]:
    """
    兼容旧 jieba.lcut 入口，保持返回列表的调用习惯。
    """
    return _lcut(sentence, cut_all=cut_all, HMM=HMM)


def cut_for_search(sentence: str, HMM: bool = True) -> Iterator[str]:
    """
    兼容旧 jieba.cut_for_search 入口，用于搜索模式分词。
    """
    return _cut_for_search(sentence, HMM=HMM)


def lcut_for_search(sentence: str, HMM: bool = True) -> list[str]:
    """
    兼容旧 jieba.lcut_for_search 入口，用于搜索模式分词列表。
    """
    return _lcut_for_search(sentence, HMM=HMM)


def __getattr__(name: str) -> Any:
    """
    将未显式封装的 jieba 属性回退到 jieba-next，减少旧调用面的迁移成本。
    """
    return getattr(_jieba_next, name)
