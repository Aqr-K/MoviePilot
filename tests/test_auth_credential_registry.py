# -*- coding: utf-8 -*-
"""CredentialProviderRegistry 单元测试（PR1，纯增量基础设施）。"""
import pytest

from app.core.auth.credentials import (
    CredentialProviderRegistry,
    CredentialRequest,
    verify_credential_provider_contract,
)
from app.core.auth.outcome import CredentialOutcome


class _Provider:
    """满足 ICredentialProvider 契约的测试桩。"""

    def __init__(self, pid="ldap", kind="directory", priority=10):
        self.provider_id = pid
        self.factor_kind = kind
        self.priority = priority

    def applies_to(self, req):
        return True

    def verify_credentials(self, req):
        return CredentialOutcome(status="not_mine")


def test_contract_accepts_valid_provider():
    ok, reasons = verify_credential_provider_contract(_Provider())
    assert ok and reasons == []


@pytest.mark.parametrize("bad", [
    _Provider(pid="bad_id"),     # 含下划线
    _Provider(pid="x" * 33),     # 超长
    _Provider(kind="weird"),     # 非法 factor_kind
    _Provider(priority="hi"),    # priority 非整数
])
def test_contract_rejects_invalid(bad):
    ok, reasons = verify_credential_provider_contract(bad)
    assert not ok and reasons


def test_contract_rejects_non_callable_method():
    p = _Provider()
    p.verify_credentials = "not callable"
    ok, reasons = verify_credential_provider_contract(p)
    assert not ok


def test_register_and_get():
    reg = CredentialProviderRegistry()
    ok, msg = reg.register(_Provider(pid="ldap"), owner="plugin-a")
    assert ok and msg == ""
    assert reg.get("ldap") is not None
    assert reg.get("missing") is None


def test_register_rejects_invalid_contract():
    reg = CredentialProviderRegistry()
    ok, msg = reg.register(_Provider(pid="bad_id"), owner="p")
    assert not ok and "provider_id" in msg


def test_collision_across_owners_rejected():
    reg = CredentialProviderRegistry()
    assert reg.register(_Provider(pid="ldap"), owner="a")[0]
    ok, msg = reg.register(_Provider(pid="ldap"), owner="b")
    assert not ok and "冲突" in msg


def test_same_owner_idempotent_overwrite():
    reg = CredentialProviderRegistry()
    assert reg.register(_Provider(pid="ldap", priority=1), owner="a")[0]
    assert reg.register(_Provider(pid="ldap", priority=2), owner="a")[0]
    assert reg.get("ldap").priority == 2


def test_unregister_by_owner():
    reg = CredentialProviderRegistry()
    reg.register(_Provider(pid="ldap"), owner="a")
    reg.register(_Provider(pid="radius"), owner="b")
    reg.unregister("a")
    assert reg.get("ldap") is None
    assert reg.get("radius") is not None


def test_all_sorted_by_priority():
    reg = CredentialProviderRegistry()
    reg.register(_Provider(pid="c", priority=30), owner="o")
    reg.register(_Provider(pid="a", priority=10), owner="o")
    reg.register(_Provider(pid="b", priority=20), owner="o")
    assert [p.provider_id for p in reg.all()] == ["a", "b", "c"]


def test_credential_request_extra_isolated_between_instances():
    a = CredentialRequest(grant_type="password", username="u", password="p")
    b = CredentialRequest(grant_type="password", username="u2", password="p2")
    assert a.extra == {} and b.extra == {}
    assert a.extra is not b.extra
