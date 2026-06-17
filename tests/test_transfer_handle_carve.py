"""
S8a 契约守护：__handle_transfer 的 7 块中 3 个无早返回子块被抽成私有 helper
（_resolve_episodes_info / _resolve_target_directory / _select_storage_opers），
入口方法保持薄编排 + 同序调用 + 原 try/finally。

本测试守护 P5 CRITICAL 的 monkey-patch 契约：p115strmhelper 通过 name-mangled
类属性 `TransferChain._TransferChain__handle_transfer` 存/换/复原补丁（patch/transfer_chain.py
:53/:64/:85）。因此入口**符号名、签名、返回契约**必须永远稳定——任何未来重构若
改名/改签名/移出 TransferChain，本测试立即失败，避免静默掐断 115 接管。

注：__handle_transfer 的完整行为需真实 downloader/media/DB 集成测试覆盖（见
tests/test_transfer_*）；本文件只断言「抽取后入口契约与结构」不变，不替代行为测试。
"""
import inspect

from app.chain.transfer import TransferChain

MANGLED = "_TransferChain__handle_transfer"


def test_handle_transfer_mangled_symbol_present():
    """p115 补丁目标符号必须存在于 TransferChain 类上。"""
    assert hasattr(TransferChain, MANGLED), (
        f"name-mangled 入口符号 {MANGLED} 丢失 → p115strmhelper 补丁的 save/install/restore 会 AttributeError"
    )


def test_handle_transfer_signature_stable():
    """签名必须保持 (self, task, callback=None)，callback 默认 None。"""
    sig = inspect.signature(getattr(TransferChain, MANGLED))
    params = list(sig.parameters)
    assert params == ["self", "task", "callback"], f"签名形参变了: {params}"
    assert sig.parameters["callback"].default is None, "callback 默认值不再是 None"


def test_extracted_helpers_present():
    """3 个抽出的无早返回 helper 必须就位（单下划线、非 name-mangled）。"""
    for h in ("_resolve_episodes_info", "_resolve_target_directory", "_select_storage_opers"):
        assert hasattr(TransferChain, h), f"抽出的 helper 缺失: {h}"


def test_handle_transfer_keeps_finally_cleanup():
    """入口方法必须保留 try/finally 清理（try_remove_job + __finish_scrape_batch_task）。"""
    src = inspect.getsource(getattr(TransferChain, MANGLED))
    assert "finally:" in src, "__handle_transfer 丢失 finally"
    assert "try_remove_job" in src and "__finish_scrape_batch_task" in src, "finally 清理动作被改动"
    # 入口编排仍按序调用 3 个 helper
    for h in ("_resolve_episodes_info", "_resolve_target_directory", "_select_storage_opers"):
        assert h in src, f"入口未调用 helper: {h}"
