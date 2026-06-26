# -*- coding: utf-8 -*-
"""PR8：集中化的认证标识符校验/派生（消除散落 5 个文件的正则与前缀重复）。"""
import pytest

from app.core.auth.identifiers import (
    CODE_RE,
    IDENTIFIER_RE,
    SUBJECT_RE,
    USERNAME_PREFIX,
    derive_local_username,
    is_valid_code,
    is_valid_identifier,
    is_valid_subject,
)


@pytest.mark.parametrize("value", ["github", "ldap-example", "a", "A1-b2", "x" * 32])
def test_identifier_accepts_valid(value):
    assert is_valid_identifier(value)
    assert IDENTIFIER_RE.match(value)


@pytest.mark.parametrize("value", ["", "has_underscore", "x" * 33, "a/b", "a.b", "中文", None])
def test_identifier_rejects_invalid(value):
    assert not is_valid_identifier(value)


@pytest.mark.parametrize("value", ["alice", "a.b-c_d", "A1", "user.name", "x" * 64])
def test_subject_accepts_valid(value):
    assert is_valid_subject(value)
    assert SUBJECT_RE.match(value)


@pytest.mark.parametrize("value", ["", ".alice", "alice.", "_x", "x_", "x" * 65, "a b", "a/b", None])
def test_subject_rejects_invalid(value):
    assert not is_valid_subject(value)


@pytest.mark.parametrize("value", ["abc", "a-b_c", "x" * 256])
def test_code_accepts_valid(value):
    assert is_valid_code(value)
    assert CODE_RE.match(value)


@pytest.mark.parametrize("value", ["", "x" * 257, "a b", "a/b", None])
def test_code_rejects_invalid(value):
    assert not is_valid_code(value)


def test_derive_local_username_is_prefix_provider_subject():
    assert USERNAME_PREFIX == "ext_"
    assert derive_local_username("github", "alice") == "ext_github_alice"
    # provider_id 不含分隔符（核心契约保证）→ (provider_id, subject) 到用户名单射
    assert derive_local_username("ldap-example", "a.b-c") == "ext_ldap-example_a.b-c"
