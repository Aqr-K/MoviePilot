# -*- coding: utf-8 -*-
"""
provisioning 护栏特征测试（PR4）：用内存 fake 注入 ``ProvisioningDeps``，逐一钉死
``resolve_or_create`` 的每条安全分支——审计点名的最高正确性风险，必须先钉绿再被使用。
"""
import types

from app.service.auth.provisioning import ProvisioningDeps, resolve_or_create

PID = "ldap"
SUBJ = "alice"
LOCAL = f"sso_{PID}_{SUBJ}"


def _user(uid=1, is_active=True):
    return types.SimpleNamespace(id=uid, is_active=is_active)


def _make_deps(*, bindings=None, users_by_name=None, users_by_id=None,
               bindings_by_user=None, create_raises=False):
    bindings = dict(bindings or {})                 # (provider_id, subject) -> user_id
    users_by_name = dict(users_by_name or {})       # name -> user
    users_by_id = dict(users_by_id or {})           # user_id -> user
    bindings_by_user = dict(bindings_by_user or {})  # user_id -> [bindings]
    state = {"created_name": None, "bind_attempts": 0}

    def get_binding(pid, subj):
        return bindings.get((pid, subj))

    def get_user_by_id(uid):
        return users_by_id.get(uid)

    def get_user_by_name(name):
        return users_by_name.get(name)

    def create_user(name, avatar=None):
        u = _user(uid=1000 + len(users_by_id), is_active=True)
        users_by_name[name] = u
        users_by_id[u.id] = u
        state["created_name"] = name

    def list_bindings_for_user(uid):
        return bindings_by_user.get(uid, [])

    def create_binding(provider_id, subject, user_id, username=None):
        state["bind_attempts"] += 1
        if create_raises:
            raise RuntimeError("unique conflict")
        bindings[(provider_id, subject)] = user_id
        bindings_by_user.setdefault(user_id, []).append((provider_id, subject))

    deps = ProvisioningDeps(get_binding, get_user_by_id, get_user_by_name,
                            create_user, list_bindings_for_user, create_binding)
    return deps, state, bindings, users_by_name, users_by_id


def _resolve(deps, *, subject=SUBJ, auto_create=True):
    return resolve_or_create(PID, subject=subject, username="alice@x", avatar=None,
                             auto_create=auto_create, deps=deps)


def test_invalid_subject_rejected():
    deps, *_ = _make_deps()
    assert _resolve(deps, subject="bad subject!") is None
    assert _resolve(deps, subject="") is None


def test_existing_binding_active_returns_user():
    u = _user(uid=7)
    deps, *_ = _make_deps(bindings={(PID, SUBJ): 7}, users_by_id={7: u})
    assert _resolve(deps) is u


def test_existing_binding_user_missing_rejected():
    deps, *_ = _make_deps(bindings={(PID, SUBJ): 7}, users_by_id={})
    assert _resolve(deps) is None


def test_existing_binding_user_inactive_rejected():
    deps, *_ = _make_deps(bindings={(PID, SUBJ): 7}, users_by_id={7: _user(7, is_active=False)})
    assert _resolve(deps) is None


def test_no_binding_no_auto_create_rejected():
    deps, *_ = _make_deps()
    assert _resolve(deps, auto_create=False) is None


def test_b4_same_name_disabled_residual_rejected():
    # 同名用户已存在但被禁用 → 拒绝复用（B-4）
    deps, *_ = _make_deps(users_by_name={LOCAL: _user(5, is_active=False)},
                          users_by_id={5: _user(5, is_active=False)})
    assert _resolve(deps) is None


def test_c1_same_name_without_binding_rejected():
    # 同名用户存在、激活，但无任何身份绑定 → 拒绝接管非外部账号（C-1）
    deps, *_ = _make_deps(users_by_name={LOCAL: _user(5, is_active=True)},
                          users_by_id={5: _user(5, is_active=True)},
                          bindings_by_user={})  # 5 无绑定
    assert _resolve(deps) is None


def test_same_name_managed_account_reused():
    # 同名用户激活且确有身份绑定（外部托管账号）→ 复用并补绑当前 subject
    u = _user(5, is_active=True)
    deps, state, bindings, *_ = _make_deps(
        users_by_name={LOCAL: u}, users_by_id={5: u},
        bindings_by_user={5: [("other", "x")]})
    assert _resolve(deps) is u
    assert bindings[(PID, SUBJ)] == 5  # 已补绑


def test_first_login_creates_user_and_binding():
    deps, state, bindings, users_by_name, _ = _make_deps()
    user = _resolve(deps)
    assert user is not None
    assert state["created_name"] == LOCAL
    assert bindings[(PID, SUBJ)] == user.id


def test_concurrent_binding_conflict_falls_back_to_existing():
    # create_binding 抛冲突，但回查发现已被并发绑定到一个激活用户 → 复用之
    bound = _user(9, is_active=True)
    calls = {"n": 0}
    created = {"done": False}

    def get_binding(pid, subj):
        # 建号前查无绑定；冲突后回查发现已存在
        calls["n"] += 1
        return 9 if calls["n"] > 1 else None

    def get_user_by_id(uid):
        return bound if uid == 9 else None

    def get_user_by_name(name):
        return _user(10, is_active=True) if created["done"] else None

    def create_user(name, avatar=None):
        created["done"] = True

    def list_bindings_for_user(uid):
        return []

    def create_binding(**kw):
        raise RuntimeError("conflict")

    deps = ProvisioningDeps(get_binding, get_user_by_id, get_user_by_name,
                            create_user, list_bindings_for_user, create_binding)
    assert resolve_or_create(PID, subject=SUBJ, auto_create=True, deps=deps) is bound


def test_binding_conflict_without_existing_returns_none():
    deps, *_ = _make_deps(create_raises=True)
    assert _resolve(deps) is None
