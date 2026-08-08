# -*- coding: utf-8 -*-
"""Task-6 TDD: RedirectStateStore 带载荷 + 原子 consume。"""
from app.core.auth.redirect import issue_state, consume_state


def test_state_payload():
    s = issue_state(flow_token="ft", provider_id="github")
    assert consume_state(s) == {"flow_token": "ft", "provider_id": "github"}
    assert consume_state(s) is None


def test_unknown():
    assert consume_state("nope") is None
