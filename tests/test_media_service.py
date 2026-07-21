"""
S7j 抽取验证：app.service.media 的 Chain 编排单测（mock Chain）。

模糊搜索（分支检索 + SEARCH_SOURCE 排序 + 分页）与刮削（识别 + 路径校验 +
scrape_metadata）下沉 service 后，通过 monkeypatch MediaChain/settings 即可在 venv
内单测，无需真实媒体识别/磁盘。search_media 为 async，测试中用 asyncio.run 驱动。
"""
import asyncio
from types import SimpleNamespace

from app.service import media as svc


class _Media:
    def __init__(self, source, key):
        self.source = source
        self._key = key

    def to_dict(self):
        return {"source": self.source, "key": self._key}


def test_search_media_sort_by_search_source_and_paginate(monkeypatch):
    async def fake_search(title, source=None):
        return None, [_Media("douban", 1), _Media("themoviedb", 2), _Media("douban", 3)]

    monkeypatch.setattr(svc, "MediaChain", lambda: SimpleNamespace(async_search=fake_search))
    monkeypatch.setattr(svc.settings, "SEARCH_SOURCE", "themoviedb,douban", raising=False)

    out = asyncio.run(svc.search_media(title="x", type="media", page=1, count=2))
    # themoviedb(order 0) 在前，其后是 douban(order 1)，分页取前 2
    assert [r["key"] for r in out] == [2, 1]


def test_search_media_page_2(monkeypatch):
    async def fake_search(title, source=None):
        return None, [_Media("douban", 1), _Media("themoviedb", 2), _Media("douban", 3)]

    monkeypatch.setattr(svc, "MediaChain", lambda: SimpleNamespace(async_search=fake_search))
    monkeypatch.setattr(svc.settings, "SEARCH_SOURCE", "themoviedb,douban", raising=False)

    out = asyncio.run(svc.search_media(title="x", type="media", page=2, count=2))
    # 排序后第 3 个：douban(key 3)
    assert [r["key"] for r in out] == [3]


def test_search_media_empty(monkeypatch):
    async def fake_search(title, source=None):
        return None, []

    monkeypatch.setattr(svc, "MediaChain", lambda: SimpleNamespace(async_search=fake_search))
    monkeypatch.setattr(svc.settings, "SEARCH_SOURCE", "", raising=False)
    out = asyncio.run(svc.search_media(title="x", type="media"))
    assert out == []


def test_search_media_person_uses_model_dump(monkeypatch):
    person = SimpleNamespace(model_dump=lambda: {"source": "themoviedb", "name": "P"})

    async def fake_persons(name):
        return [person]

    monkeypatch.setattr(
        svc, "MediaChain", lambda: SimpleNamespace(async_search_persons=fake_persons)
    )
    monkeypatch.setattr(svc.settings, "SEARCH_SOURCE", "themoviedb", raising=False)
    out = asyncio.run(svc.search_media(title="p", type="person"))
    assert out == [{"source": "themoviedb", "name": "P"}]


# ---------- scrape_path ----------

def test_scrape_path_invalid():
    assert svc.scrape_path(None)[0] is False
    ok, msg = svc.scrape_path(SimpleNamespace(path=""))
    assert ok is False
    assert "刮削路径无效" in msg


def test_scrape_path_recognize_fail(monkeypatch):
    fi = SimpleNamespace(path="/x/m.mkv")
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(recognize_by_path=lambda p, source=None, obtain_images=False: None),
    )
    ok, msg = svc.scrape_path(fi, storage="rclone")  # 非 local 跳过 Path.exists
    assert ok is False
    assert "无法识别媒体信息" in msg


def test_scrape_path_local_not_exist(monkeypatch):
    fi = SimpleNamespace(path="/nonexistent/m.mkv")
    ctx = SimpleNamespace(media_info=SimpleNamespace(), meta_info=SimpleNamespace())
    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(
            recognize_by_path=lambda p, source=None, obtain_images=False: ctx,
            scrape_metadata=lambda **k: None,
        ),
    )
    ok, msg = svc.scrape_path(fi, storage="local")
    assert ok is False
    assert "刮削路径不存在" in msg


def test_scrape_path_success(monkeypatch, tmp_path):
    f = tmp_path / "m.mkv"
    f.write_text("x")
    fi = SimpleNamespace(path=str(f))
    ctx = SimpleNamespace(media_info=SimpleNamespace(), meta_info=SimpleNamespace())
    scraped = {}

    def fake_scrape(**k):
        scraped.update(k)

    monkeypatch.setattr(
        svc, "MediaChain",
        lambda: SimpleNamespace(
            recognize_by_path=lambda p, source=None, obtain_images=False: ctx,
            scrape_metadata=fake_scrape,
        ),
    )
    ok, msg = svc.scrape_path(fi, storage="local")
    assert ok is True
    assert "刮削完成" in msg
    assert scraped["overwrite"] is True
