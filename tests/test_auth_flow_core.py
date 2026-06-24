# -*- coding: utf-8 -*-
"""PR9：认证流程状态机核心 —— 组合策略 ``AuthRequirement`` + 跨请求状态 ``AuthContext``。

证明可任意组合（AND / OR / N-of-M、任意嵌套）地表达"需要满足哪些步骤"，且状态不可变、可 JSON 序列化
（供 FlowStore 跨请求承载多步/多轮流程）。
"""
import json

import pytest

from app.core.auth.flow import AllOf, AnyOf, AuthContext, NOf, StepRef


# ----------------------------- 组合策略 is_satisfied -----------------------------
def test_stepref_satisfied():
    r = StepRef("password")
    assert not r.is_satisfied(set())
    assert r.is_satisfied({"password"})


def test_allof_requires_all():
    r = AllOf([StepRef("a"), StepRef("b")])
    assert not r.is_satisfied({"a"})
    assert r.is_satisfied({"a", "b"})


def test_anyof_requires_one():
    r = AnyOf([StepRef("a"), StepRef("b")])
    assert not r.is_satisfied(set())
    assert r.is_satisfied({"b"})


def test_nof_requires_n():
    r = NOf(2, [StepRef("a"), StepRef("b"), StepRef("c")])
    assert not r.is_satisfied({"a"})
    assert r.is_satisfied({"a", "c"})
    assert r.is_satisfied({"a", "b", "c"})


def test_nested_credential_then_mfa():
    # 默认流程语义：凭证(任一) AND 第二因子(任一)
    r = AllOf([AnyOf([StepRef("password"), StepRef("ldap")]),
               AnyOf([StepRef("otp"), StepRef("passkey")])])
    assert not r.is_satisfied({"password"})
    assert r.is_satisfied({"password", "otp"})
    assert r.is_satisfied({"ldap", "passkey"})


def test_nof_inside_allof():
    # 凭证 AND（3 选 2 的强 MFA）
    r = AllOf([StepRef("password"), NOf(2, [StepRef("otp"), StepRef("sms"), StepRef("passkey")])])
    assert not r.is_satisfied({"password", "otp"})
    assert r.is_satisfied({"password", "otp", "sms"})


# ----------------------------- 候选步骤 candidates -----------------------------
def test_candidates_credential_then_mfa():
    r = AllOf([AnyOf([StepRef("password"), StepRef("ldap")]),
               AnyOf([StepRef("otp"), StepRef("passkey")])])
    assert r.candidates(set()) == {"password", "ldap", "otp", "passkey"}
    assert r.candidates({"password"}) == {"otp", "passkey"}   # 凭证满足 → 仅剩 MFA 候选
    assert r.candidates({"password", "otp"}) == set()         # 全满足 → 无候选


def test_candidates_nof_shrinks():
    r = NOf(2, [StepRef("a"), StepRef("b"), StepRef("c")])
    assert r.candidates({"a"}) == {"b", "c"}                  # 还差 1 个，b/c 皆候选
    assert r.candidates({"a", "b"}) == set()                  # 已达 2，无候选


def test_leaf_step_ids():
    r = AllOf([AnyOf([StepRef("password"), StepRef("ldap")]), StepRef("otp")])
    assert r.leaf_step_ids() == {"password", "ldap", "otp"}


# ----------------------------- 状态不可变 + 序列化 -----------------------------
def test_with_satisfied_returns_new_copy():
    c = AuthContext(flow_id="f1", username="alice")
    c2 = c.with_satisfied("password")
    assert "password" not in c.satisfied_steps               # 原对象不变（immutable）
    assert c2.satisfied_steps == frozenset({"password"})
    assert (c2.flow_id, c2.username) == ("f1", "alice")


def test_with_resolved_user_returns_new_copy():
    c = AuthContext(flow_id="f1", username="alice")
    c2 = c.with_resolved_user(user_id=42, mfa_satisfied=True)
    assert c.resolved_user_id is None and c.mfa_satisfied is False
    assert c2.resolved_user_id == 42 and c2.mfa_satisfied is True


def test_with_challenge_and_attempt():
    c = AuthContext(flow_id="f1").with_challenge("sms", {"sent": True}).with_attempt()
    assert c.challenges["sms"] == {"sent": True}
    assert c.attempts == 1


def test_context_json_roundtrip():
    c = (AuthContext(flow_id="f1", username="alice")
         .with_satisfied("password")
         .with_resolved_user(user_id=7)
         .with_challenge("sms", {"sent": True}))
    d = c.to_dict()
    json.dumps(d)                                             # 必须可 JSON 序列化
    c2 = AuthContext.from_dict(d)
    assert c2.flow_id == "f1"
    assert c2.username == "alice"
    assert c2.satisfied_steps == frozenset({"password"})
    assert c2.resolved_user_id == 7
    assert c2.challenges["sms"] == {"sent": True}
