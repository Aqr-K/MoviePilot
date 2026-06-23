# -*- coding: utf-8 -*-
"""ChallengeStore 单元测试（PR1）：put/get/consume/TTL（注入时钟，确定性，无 sleep）。"""
from app.core.challenge_store import ChallengeStore


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_put_get():
    store = ChallengeStore(ttl_seconds=600)
    store.put("u1:sms", {"code": "999"})
    assert store.get("u1:sms") == {"code": "999"}
    assert store.get("missing") is None


def test_get_returns_copy_not_reference():
    store = ChallengeStore()
    store.put("k", {"code": "1"})
    got = store.get("k")
    got["code"] = "tampered"
    assert store.get("k") == {"code": "1"}


def test_consume_is_single_use():
    store = ChallengeStore()
    store.put("k", {"code": "1"})
    assert store.consume("k") == {"code": "1"}
    assert store.consume("k") is None
    assert store.get("k") is None


def test_ttl_expiry_on_get():
    clock = _Clock(1000.0)
    store = ChallengeStore(ttl_seconds=300, now=clock)
    store.put("k", {"code": "1"})
    clock.t = 1000.0 + 299
    assert store.get("k") == {"code": "1"}
    clock.t = 1000.0 + 301
    assert store.get("k") is None


def test_consume_expired_returns_none():
    clock = _Clock(0.0)
    store = ChallengeStore(ttl_seconds=10, now=clock)
    store.put("k", {})
    clock.t = 100.0
    assert store.consume("k") is None


def test_delete():
    store = ChallengeStore()
    store.put("k", {})
    store.delete("k")
    assert store.get("k") is None
