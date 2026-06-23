# -*- coding: utf-8 -*-
"""
PR5：``try_credential_providers`` 主认证 fallback 行为测试（注入 providers + 内存 deps，db-free）。
覆盖：空、not_mine、不适用、成功建号、已满足MFA、provider 异常跳过、priority 顺序、provisioning 护栏拒绝。
"""
import types

from app.core.auth.outcome import CredentialOutcome
from app.service.auth.orchestrator import try_credential_providers
from app.service.auth.provisioning import ProvisioningDeps


def _creds(username="alice"):
    return types.SimpleNamespace(grant_type="password", username=username,
                                 password="x", code=None, mfa_code=None)


class _Prov:
    factor_kind = "directory"

    def __init__(self, pid="ldap", status="success", priority=10, applies=True,
                 auto_create=True, username="alice", raises=False, mfa_satisfied=False):
        self.provider_id = pid
        self.priority = priority
        self.auto_create = auto_create
        self._status = status
        self._applies = applies
        self._username = username
        self._raises = raises
        self._mfa = mfa_satisfied

    def applies_to(self, req):
        if self._raises:
            raise RuntimeError("boom")
        return self._applies

    def verify_credentials(self, req):
        return CredentialOutcome(status=self._status, username=self._username,
                                 mfa_already_satisfied=self._mfa)


def _ok_deps(created_user):
    """auto_create 成功路径：无绑定、无同名 → 建号 → 返回新用户。"""
    state = {"created": False}

    def get_binding(p, s):
        return None

    def get_user_by_id(uid):
        return created_user

    def get_user_by_name(n):
        return created_user if state["created"] else None

    def create_user(name, avatar=None):
        state["created"] = True

    def list_bindings_for_user(uid):
        return []

    def create_binding(**kw):
        pass

    return ProvisioningDeps(get_binding, get_user_by_id, get_user_by_name,
                            create_user, list_bindings_for_user, create_binding)


def _reject_deps(active_user_no_binding):
    """C-1 拒绝路径：同名激活用户但无任何绑定 → resolve_or_create 返回 None。"""
    def get_binding(p, s):
        return None

    def get_user_by_id(uid):
        return None

    def get_user_by_name(n):
        return active_user_no_binding

    def create_user(**k):
        raise AssertionError("不应建号")

    def list_bindings_for_user(uid):
        return []

    def create_binding(**kw):
        raise AssertionError("不应绑定")

    return ProvisioningDeps(get_binding, get_user_by_id, get_user_by_name,
                            create_user, list_bindings_for_user, create_binding)


def test_no_providers_returns_none():
    assert try_credential_providers(_creds(), providers=[]) is None


def test_not_mine_returns_none():
    deps = _ok_deps(types.SimpleNamespace(id=1, is_active=True))
    assert try_credential_providers(_creds(), providers=[_Prov(status="not_mine")], deps=deps) is None


def test_not_applies_skipped():
    deps = _ok_deps(types.SimpleNamespace(id=1, is_active=True))
    assert try_credential_providers(_creds(), providers=[_Prov(applies=False)], deps=deps) is None


def test_success_returns_resolved_identity():
    user = types.SimpleNamespace(id=42, is_active=True)
    res = try_credential_providers(_creds(), providers=[_Prov()], deps=_ok_deps(user))
    assert res is not None and res.user is user and res.apply_mfa is True


def test_mfa_already_satisfied_skips_mfa():
    user = types.SimpleNamespace(id=42, is_active=True)
    res = try_credential_providers(_creds(), providers=[_Prov(mfa_satisfied=True)], deps=_ok_deps(user))
    assert res is not None and res.apply_mfa is False


def test_provider_exception_skipped():
    deps = _ok_deps(types.SimpleNamespace(id=1, is_active=True))
    assert try_credential_providers(_creds(), providers=[_Prov(raises=True)], deps=deps) is None


def test_priority_order_lower_first_wins():
    user = types.SimpleNamespace(id=7, is_active=True)
    # 显式按 priority 升序传入：首个（高优先）not_mine 让位给次个 success
    p_high = _Prov(pid="first", status="not_mine", priority=1)
    p_low = _Prov(pid="second", status="success", priority=2)
    res = try_credential_providers(_creds(), providers=[p_high, p_low], deps=_ok_deps(user))
    assert res is not None and res.user is user


def test_provisioning_rejected_returns_none():
    active = types.SimpleNamespace(id=9, is_active=True)
    res = try_credential_providers(_creds(), providers=[_Prov()], deps=_reject_deps(active))
    assert res is None
