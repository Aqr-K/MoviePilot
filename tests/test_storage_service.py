"""
S7i 抽取验证：app.service.storage 的 Chain 编排单测（mock Chain）。

目录列举（过滤+排序）与递归智能重命名编排下沉 service 后，通过 monkeypatch
StorageChain/MediaChain/TransferChain/ProgressHelper 即可在 venv 内单测，无需真实
存储/媒体识别/文件系统。
"""
from types import SimpleNamespace

import pytest

from app.service import storage as svc


def _fi(name, modify_time=0, ftype="file", extension=None, path="/d/"):
    return SimpleNamespace(
        name=name, modify_time=modify_time, type=ftype, extension=extension, path=path
    )


# ---------- list_directory ----------

def test_list_directory_empty(monkeypatch):
    monkeypatch.setattr(svc, "StorageChain", lambda: SimpleNamespace(list_files=lambda fi: []))
    assert svc.list_directory(SimpleNamespace()) == []


def test_list_directory_keyword_filter_case_insensitive(monkeypatch):
    files = [_fi("a.mkv"), _fi("b.txt"), _fi("c.MKV")]
    monkeypatch.setattr(
        svc, "StorageChain", lambda: SimpleNamespace(list_files=lambda fi: list(files))
    )
    out = svc.list_directory(SimpleNamespace(), sort="name", keyword="*.mkv")
    assert [f.name for f in out] == ["a.mkv", "c.MKV"]


def test_list_directory_sort_time_desc(monkeypatch):
    files = [_fi("old", modify_time=1), _fi("new", modify_time=5), _fi("mid", modify_time=3)]
    monkeypatch.setattr(
        svc, "StorageChain", lambda: SimpleNamespace(list_files=lambda fi: list(files))
    )
    out = svc.list_directory(SimpleNamespace(), sort="updated_at")
    assert [f.name for f in out] == ["new", "mid", "old"]


# ---------- batch_recursive_rename ----------

@pytest.fixture
def exts(monkeypatch):
    monkeypatch.setattr(svc.settings, "RMT_MEDIAEXT", [".mkv"], raising=False)
    monkeypatch.setattr(svc.settings, "RMT_SUBEXT", [], raising=False)
    monkeypatch.setattr(svc.settings, "RMT_AUDIOEXT", [], raising=False)


def _progress():
    return SimpleNamespace(start=lambda: None, update=lambda **k: None, end=lambda: None)


def _ctx():
    return SimpleNamespace(media_info=SimpleNamespace(), meta_info=SimpleNamespace())


def test_batch_no_subfiles(monkeypatch, exts):
    monkeypatch.setattr(svc, "TransferChain", lambda: SimpleNamespace())
    monkeypatch.setattr(svc, "StorageChain", lambda: SimpleNamespace(list_files=lambda fi: []))
    ok, msg = svc.batch_recursive_rename(SimpleNamespace(path="/d/"))
    assert ok is True
    assert msg == ""


def test_batch_recognize_fail(monkeypatch, exts):
    sub = _fi("a.mkv", extension="mkv")
    monkeypatch.setattr(svc, "TransferChain", lambda: SimpleNamespace(recommend_name=lambda **k: "x"))
    monkeypatch.setattr(
        svc, "StorageChain",
        lambda: SimpleNamespace(list_files=lambda fi: [sub], rename_file=lambda *a: True),
    )
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(recognize_by_path=lambda p, obtain_images: None),
    )
    monkeypatch.setattr(svc, "ProgressHelper", lambda key: _progress())
    ok, msg = svc.batch_recursive_rename(SimpleNamespace(path="/d/"))
    assert ok is False
    assert "未识别到媒体信息" in msg


def test_batch_recommend_fail(monkeypatch, exts):
    sub = _fi("a.mkv", extension="mkv")
    monkeypatch.setattr(
        svc, "TransferChain",
        lambda: SimpleNamespace(recommend_name=lambda meta, mediainfo: None),
    )
    monkeypatch.setattr(
        svc, "StorageChain",
        lambda: SimpleNamespace(list_files=lambda fi: [sub], rename_file=lambda *a: True),
    )
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(recognize_by_path=lambda p, obtain_images: _ctx()),
    )
    monkeypatch.setattr(svc, "ProgressHelper", lambda key: _progress())
    ok, msg = svc.batch_recursive_rename(SimpleNamespace(path="/d/"))
    assert ok is False
    assert "未识别到新名称" in msg


def test_batch_rename_fail(monkeypatch, exts):
    sub = _fi("a.mkv", extension="mkv")
    monkeypatch.setattr(
        svc, "TransferChain",
        lambda: SimpleNamespace(recommend_name=lambda meta, mediainfo: "/new/Name.mkv"),
    )
    monkeypatch.setattr(
        svc, "StorageChain",
        lambda: SimpleNamespace(list_files=lambda fi: [sub], rename_file=lambda *a: False),
    )
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(recognize_by_path=lambda p, obtain_images: _ctx()),
    )
    monkeypatch.setattr(svc, "ProgressHelper", lambda key: _progress())
    ok, msg = svc.batch_recursive_rename(SimpleNamespace(path="/d/"))
    assert ok is False
    assert "重命名失败" in msg


def test_batch_success_skips_dir_and_nonmedia(monkeypatch, exts):
    subs = [
        _fi("sub", ftype="dir"),
        _fi("note.txt", extension="txt"),
        _fi("m.mkv", extension="mkv"),
    ]
    renamed = []

    def rf(sf, nn):
        renamed.append((sf.name, nn))
        return True

    monkeypatch.setattr(
        svc, "TransferChain",
        lambda: SimpleNamespace(recommend_name=lambda meta, mediainfo: "/x/New.mkv"),
    )
    monkeypatch.setattr(
        svc, "StorageChain",
        lambda: SimpleNamespace(list_files=lambda fi: list(subs), rename_file=rf),
    )
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(recognize_by_path=lambda p, obtain_images: _ctx()),
    )
    monkeypatch.setattr(svc, "ProgressHelper", lambda key: _progress())
    ok, msg = svc.batch_recursive_rename(SimpleNamespace(path="/d/"))
    assert ok is True
    assert msg == ""
    # 仅 .mkv 被重命名，使用推荐路径的 basename
    assert renamed == [("m.mkv", "New.mkv")]
