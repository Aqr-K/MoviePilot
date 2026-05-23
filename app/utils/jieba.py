"""中文分词工具。"""

from fast_jieba import cut as fast_jieba_cut


def cut(text: str, HMM: bool = True, cut_all: bool = False) -> list[str]:
    """
    使用 fast-jieba 执行中文分词，并兼容 jieba.cut 的常用参数名。
    """
    return fast_jieba_cut(text, hmm=HMM, cut_all=cut_all)
