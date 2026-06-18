"""
S8a/S8b 契约守护：__handle_transfer 的 7 块已全部抽成私有 helper
（识别块 _recognize_for_transfer（多值回流）；无早返回块 _resolve_episodes_info/
_resolve_target_directory/_select_storage_opers/_apply_scrap_follow_tmdb；哨兵块
_migrate_or_skip；终末 tail 块 _run_transfer_and_dispatch），入口方法退化为薄编排
+ 同序调用 + 原 try/finally。

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
    """7 个抽出的 helper 必须就位（单下划线、非 name-mangled）。"""
    for h in ("_recognize_for_transfer", "_resolve_episodes_info", "_resolve_target_directory", "_select_storage_opers", "_apply_scrap_follow_tmdb", "_migrate_or_skip", "_run_transfer_and_dispatch"):
        assert hasattr(TransferChain, h), f"抽出的 helper 缺失: {h}"


def test_handle_transfer_keeps_finally_cleanup():
    """入口方法必须保留 try/finally 清理（try_remove_job + __finish_scrape_batch_task）。"""
    src = inspect.getsource(getattr(TransferChain, MANGLED))
    assert "finally:" in src, "__handle_transfer 丢失 finally"
    assert "try_remove_job" in src and "__finish_scrape_batch_task" in src, "finally 清理动作被改动"
    # 入口编排仍按序调用 7 个 helper
    for h in ("_recognize_for_transfer", "_resolve_episodes_info", "_resolve_target_directory", "_select_storage_opers", "_apply_scrap_follow_tmdb", "_migrate_or_skip", "_run_transfer_and_dispatch"):
        assert h in src, f"入口未调用 helper: {h}"


# 入口编排里 7 个 helper 的调用先后顺序（与 __handle_transfer 源码出现次序一致）
_HELPER_CALL_ORDER = (
    "_recognize_for_transfer",
    "_apply_scrap_follow_tmdb",
    "_migrate_or_skip",
    "_resolve_episodes_info",
    "_resolve_target_directory",
    "_select_storage_opers",
    "_run_transfer_and_dispatch",
)


def test_handle_transfer_helper_call_order():
    """守卫调用顺序：未来重排 helper 调用次序会立即失败（补审查 LOW 项）。"""
    src = inspect.getsource(getattr(TransferChain, MANGLED))
    positions = [src.index(h) for h in _HELPER_CALL_ORDER]
    assert positions == sorted(positions), (
        f"helper 调用顺序被改动，期望 {_HELPER_CALL_ORDER}，实际源码次序错位"
    )


# ---------- S8b：_apply_scrap_follow_tmdb 行为单测（mock 历史 Oper，无需 DB） ----------
import types  # noqa: E402

from app.core.config import settings  # noqa: E402


def _mediainfo(title="New Title", tmdb_id=1, type_value="电影"):
    return types.SimpleNamespace(
        title=title, tmdb_id=tmdb_id, type=types.SimpleNamespace(value=type_value)
    )


def _transferhis(history):
    return types.SimpleNamespace(get_by_type_tmdbid=lambda tmdbid, mtype: history)


def _apply(mediainfo, changed, transferhis):
    # 该 helper 不使用 self，unbound 调用传 None
    return TransferChain._apply_scrap_follow_tmdb(None, mediainfo, changed, transferhis)


def test_scrap_follow_enabled_skips(monkeypatch):
    """开启跟随 TMDB 时整块跳过：title 不动，mediainfo_changed 原样返回。"""
    monkeypatch.setattr(settings, "SCRAP_FOLLOW_TMDB", True, raising=False)
    mi = _mediainfo(title="New Title")
    out = _apply(mi, False, _transferhis(types.SimpleNamespace(title="Old Title")))
    assert out is False
    assert mi.title == "New Title"


def test_scrap_follow_disabled_overwrites_title(monkeypatch):
    """未开启 + 历史 title 不同：就地覆盖 mediainfo.title，返回 True。"""
    monkeypatch.setattr(settings, "SCRAP_FOLLOW_TMDB", False, raising=False)
    mi = _mediainfo(title="New Title")
    out = _apply(mi, False, _transferhis(types.SimpleNamespace(title="Old Title")))
    assert out is True
    assert mi.title == "Old Title"


def test_scrap_follow_disabled_same_title_no_change(monkeypatch):
    """未开启 + 历史 title 相同：不覆盖，mediainfo_changed 原样。"""
    monkeypatch.setattr(settings, "SCRAP_FOLLOW_TMDB", False, raising=False)
    mi = _mediainfo(title="Same")
    out = _apply(mi, False, _transferhis(types.SimpleNamespace(title="Same")))
    assert out is False
    assert mi.title == "Same"


def test_scrap_follow_disabled_no_history_keeps_input(monkeypatch):
    """未开启 + 无历史：不覆盖，输入的 mediainfo_changed 透传。"""
    monkeypatch.setattr(settings, "SCRAP_FOLLOW_TMDB", False, raising=False)
    mi = _mediainfo(title="New Title")
    out = _apply(mi, True, _transferhis(None))
    assert out is True
    assert mi.title == "New Title"


# ---------- S8b：_migrate_or_skip 行为单测（哨兵协议，mock jobview，无需 DB） ----------


def _fake_self(migrate_result, calls):
    """伪 self：仅需 jobview.migrate_task；记录被传入的 task 以验证调用。"""
    return types.SimpleNamespace(
        jobview=types.SimpleNamespace(
            migrate_task=lambda t: (calls.append(t) or migrate_result)
        )
    )


def _task(name="file.mkv"):
    return types.SimpleNamespace(
        mediainfo="ORIGINAL", fileitem=types.SimpleNamespace(name=name)
    )


def test_migrate_skip_not_changed_returns_none_no_migrate():
    """mediainfo_changed=False：返回 None（继续），不调用 migrate，不回写 task.mediainfo。"""
    calls = []
    s = _fake_self(True, calls)
    task = _task()
    mi = object()
    out = TransferChain._migrate_or_skip(s, task, mi, False)
    assert out is None
    assert calls == []
    assert task.mediainfo == "ORIGINAL"


def test_migrate_changed_success_returns_none_sets_mediainfo():
    """变更 + migrate 成功：回写 task.mediainfo，migrate 调用一次，返回 None（继续）。"""
    calls = []
    s = _fake_self(True, calls)
    task = _task()
    mi = object()
    out = TransferChain._migrate_or_skip(s, task, mi, True)
    assert out is None
    assert task.mediainfo is mi
    assert calls == [task]


def test_migrate_changed_duplicate_returns_bail_tuple():
    """变更 + migrate 报重复：先回写 mediainfo，再返回精确 (False, '...已在整理队列中') 哨兵。"""
    calls = []
    s = _fake_self(False, calls)
    task = _task(name="movie.mkv")
    mi = object()
    out = TransferChain._migrate_or_skip(s, task, mi, True)
    assert out == (False, "movie.mkv 已在整理队列中")
    assert task.mediainfo is mi
    assert calls == [task]
