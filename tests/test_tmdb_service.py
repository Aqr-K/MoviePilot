"""
S7k 抽取验证：app.service.tmdb 的 Chain 分发编排单测（mock Chain）。

类似/推荐/演员阵容按 type_name（电影/电视剧）分发到 TmdbChain 不同方法 + to_dict
映射。下沉 service 后通过 monkeypatch TmdbChain 在 venv 内单测（async，用 asyncio.run）。
"""
import asyncio
from types import SimpleNamespace

from app.service import tmdb as svc


class _M:
    def __init__(self, k):
        self._k = k

    def to_dict(self):
        return {"k": self._k}


def test_similar_movie_branch(monkeypatch):
    async def mv(tmdbid):
        return [_M(1), _M(2)]

    async def tv(tmdbid):
        return [_M(9)]

    monkeypatch.setattr(
        svc, "TmdbChain",
        lambda: SimpleNamespace(async_movie_similar=mv, async_tv_similar=tv),
    )
    assert asyncio.run(svc.similar_medias(1, "电影")) == [{"k": 1}, {"k": 2}]


def test_similar_tv_branch(monkeypatch):
    async def mv(tmdbid):
        return [_M(1)]

    async def tv(tmdbid):
        return [_M(9)]

    monkeypatch.setattr(
        svc, "TmdbChain",
        lambda: SimpleNamespace(async_movie_similar=mv, async_tv_similar=tv),
    )
    assert asyncio.run(svc.similar_medias(1, "电视剧")) == [{"k": 9}]


def test_similar_other_type_returns_empty():
    # 未知（合法 MediaType 但非 电影/电视剧）-> else 分支 -> []
    assert asyncio.run(svc.similar_medias(1, "未知")) == []


def test_similar_empty_result(monkeypatch):
    async def mv(tmdbid):
        return None

    monkeypatch.setattr(svc, "TmdbChain", lambda: SimpleNamespace(async_movie_similar=mv))
    assert asyncio.run(svc.similar_medias(1, "电影")) == []


def test_recommend_movie_branch(monkeypatch):
    async def mv(tmdbid):
        return [_M(5)]

    monkeypatch.setattr(svc, "TmdbChain", lambda: SimpleNamespace(async_movie_recommend=mv))
    assert asyncio.run(svc.recommend_medias(2, "电影")) == [{"k": 5}]


def test_credits_movie_passes_page(monkeypatch):
    calls = {}

    async def mc(tmdbid, page):
        calls["page"] = page
        return [SimpleNamespace(name="P")]

    monkeypatch.setattr(svc, "TmdbChain", lambda: SimpleNamespace(async_movie_credits=mc))
    out = asyncio.run(svc.credits_persons(3, "电影", page=4))
    assert calls["page"] == 4
    assert len(out) == 1


def test_credits_other_type_returns_empty():
    assert asyncio.run(svc.credits_persons(3, "未知")) == []
