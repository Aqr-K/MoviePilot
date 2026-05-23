import jieba

from app.utils.jieba import cut


def test_cut_accepts_legacy_hmm_argument():
    """验证兼容封装仍支持旧 jieba.cut 的 HMM 参数名。"""
    words = cut("台湾后台测试", HMM=False)

    assert "".join(words) == "台湾后台测试"
    assert "后台" in words


def test_legacy_jieba_import_uses_compat_entrypoint():
    """验证插件仍可通过旧 jieba.cut 入口使用主程序分词实现。"""
    words = list(jieba.cut("台湾后台测试", HMM=False))

    assert "".join(words) == "台湾后台测试"
    assert "后台" in words
