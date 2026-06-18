"""
S7g 抽取验证：app.service.history 纯逻辑单测。

history 端点因 import app.agent / app.utils.jieba 触发 jieba_next 缺口，在本环境
不可导入，这些逻辑（含安全相关的 glob→SQL LIKE 转义）此前无 venv 覆盖；
抽出到不依赖 agent 的 service 后可在 venv 直接覆盖。
"""
from types import SimpleNamespace

from app.service import history as svc


def _h(**kw):
    base = dict(
        id=1,
        status=True,
        title="T",
        type="电影",
        category="C",
        year="2020",
        seasons="",
        episodes="",
        src="/src",
        src_fileitem=None,
        src_storage="local",
        dest="/dest",
        dest_storage="local",
        mode="copy",
        tmdbid=1,
        doubanid=2,
        errmsg=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_normalize_history_ids_dedup_preserves_order():
    assert svc.normalize_history_ids([3, 1, 3, 2, 1]) == [3, 1, 2]


def test_normalize_history_ids_empty():
    assert svc.normalize_history_ids([]) == []


def test_build_manual_redo_template_context_basic():
    h = _h(id=7, status=True, title="Foo", seasons="S01", episodes="E02", src="/a/b")
    ctx = svc.build_manual_redo_template_context(h)
    assert ctx["history_id"] == 7
    assert ctx["current_status"] == "success"
    assert ctx["recognized_title"] == "Foo"
    assert ctx["season_episode"] == "S01E02"
    assert ctx["source_path"] == "/a/b"


def test_build_manual_redo_template_context_src_fileitem_dict_preferred():
    h = _h(src_fileitem={"path": "/from/item"}, src="/fallback")
    ctx = svc.build_manual_redo_template_context(h)
    assert ctx["source_path"] == "/from/item"


def test_build_manual_redo_template_context_failed_and_defaults():
    h = _h(status=False, title=None, type=None, tmdbid=None, errmsg="boom")
    ctx = svc.build_manual_redo_template_context(h)
    assert ctx["current_status"] == "failed"
    assert ctx["recognized_title"] == "unknown"
    assert ctx["media_type"] == "unknown"
    assert ctx["tmdbid"] == "none"
    assert ctx["error_message"] == "boom"


def test_format_manual_redo_record_context():
    h = _h(id=5, status=True, title="Bar")
    out = svc.format_manual_redo_record_context(h)
    assert out.startswith("Record #5:")
    assert "- Current recognized title: Bar" in out


def test_build_batch_template_context():
    hs = [_h(id=1), _h(id=2)]
    ctx = svc.build_batch_manual_redo_template_context(hs)
    assert ctx["history_ids_csv"] == "1, 2"
    assert ctx["history_count"] == 2
    assert "Record #1:" in ctx["records_context"]
    assert "Record #2:" in ctx["records_context"]
    assert "\n\n" in ctx["records_context"]


def test_glob_to_like_escapes_and_maps():
    # * -> %, ? -> _
    assert svc.glob_to_like("a*b?c") == "a%b_c"
    # 字面 % 和 _ 被转义
    assert svc.glob_to_like("50%_x") == "50\\%\\_x"
    # 字面反斜杠被转义
    assert svc.glob_to_like("a\\b") == "a\\\\b"


def test_glob_to_like_escape_then_map_order():
    # 字面 %（转义）与 glob *（映射）共存：先转义字面、再映射通配
    assert svc.glob_to_like("%*") == "\\%%"
