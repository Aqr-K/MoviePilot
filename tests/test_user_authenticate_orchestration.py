# -*- coding: utf-8 -*-
"""
UserChain.user_authenticate 编排回归：锁住对外返回契约（login.py 依赖），护住 A 档内部清理。

外部契约（app/api/endpoints/login.py:29）：
  - 成功 → (True, User)
  - 需要二次验证 → (False, "MFA_REQUIRED")
  - 失败 → (False, <错误串>)

关键不变量：
  - grant_type=="password" 走 MFA（password-success 与 aux-success 两条子路均校验 MFA）；
  - grant_type=="authorization_code" **不走 MFA**（即便 _verify_mfa 会要求，也直接放行）；
  - 各失败串与现行一致。

测试以 mock 替换 password_authenticate / auxiliary_authenticate / _verify_mfa 与 settings，
只验证编排（不触真实 DB/模块/事件）。
"""
from unittest import TestCase
from unittest.mock import patch

from app.chain.user import UserChain, PASSWORD_INVALID_CREDENTIALS_MESSAGE


class _FakeUser:
    def __init__(self, name="u"):
        self.name = name
        self.id = 1
        self.is_superuser = False


class _FalsyUser(_FakeUser):
    """真值为 False 的用户：成功门用 is None 而非真值判断，故仍应判为认证成功。"""
    def __bool__(self):
        return False


def _authenticate(*, grant_type="password", pw=(False, "x"), aux=(False, "x"),
                  mfa=True, aux_enable=False, mfa_code=None):
    """以受控 mock 跑 user_authenticate，返回其对外结果。"""
    chain = UserChain.__new__(UserChain)  # 绕过 __init__，避免初始化真实依赖
    # AuthCredentials 对 authorization_code 要求必填 code
    code = "authcode" if grant_type == "authorization_code" else None
    with patch.object(UserChain, "password_authenticate", staticmethod(lambda credentials: pw)), \
            patch.object(UserChain, "auxiliary_authenticate", lambda self, credentials: aux), \
            patch.object(UserChain, "_verify_mfa", staticmethod(lambda user, code: mfa)), \
            patch("app.chain.user.settings") as s:
        s.AUXILIARY_AUTH_ENABLE = aux_enable
        return chain.user_authenticate(username="u", password="p", mfa_code=mfa_code,
                                       code=code, grant_type=grant_type)


class UserAuthenticateOrchestrationTest(TestCase):

    # ---- password grant：本地密码 ----
    def test_password_success_no_mfa(self):
        user = _FakeUser()
        self.assertEqual(_authenticate(pw=(True, user), mfa=True), (True, user))

    def test_falsy_user_still_authenticated(self):
        # 成功门用 is None：真值为 False 的合法用户也应判为成功（不被误拒）
        user = _FalsyUser()
        success, returned = _authenticate(pw=(True, user), mfa=True)
        self.assertTrue(success)
        self.assertIs(returned, user)

    def test_password_success_mfa_required(self):
        user = _FakeUser()
        self.assertEqual(_authenticate(pw=(True, user), mfa="MFA_REQUIRED"), (False, "MFA_REQUIRED"))

    def test_password_success_mfa_failed(self):
        user = _FakeUser()
        self.assertEqual(_authenticate(pw=(True, user), mfa=False),
                         (False, PASSWORD_INVALID_CREDENTIALS_MESSAGE))

    # ---- password grant：本地失败 → 辅助认证 ----
    def test_password_fail_aux_disabled(self):
        self.assertEqual(_authenticate(pw=(False, "x"), aux_enable=False),
                         (False, PASSWORD_INVALID_CREDENTIALS_MESSAGE))

    def test_password_fail_aux_success_with_mfa(self):
        # 辅助认证成功的用户在 password grant 下仍需过 MFA
        aux_user = _FakeUser("aux")
        self.assertEqual(_authenticate(pw=(False, "x"), aux=(True, aux_user), aux_enable=True, mfa=True),
                         (True, aux_user))

    def test_password_fail_aux_success_mfa_required(self):
        aux_user = _FakeUser("aux")
        self.assertEqual(_authenticate(pw=(False, "x"), aux=(True, aux_user), aux_enable=True, mfa="MFA_REQUIRED"),
                         (False, "MFA_REQUIRED"))

    def test_password_fail_aux_failed(self):
        self.assertEqual(_authenticate(pw=(False, "x"), aux=(False, "x"), aux_enable=True),
                         (False, PASSWORD_INVALID_CREDENTIALS_MESSAGE))

    # ---- authorization_code grant：不走 MFA ----
    def test_authorization_code_aux_success_skips_mfa(self):
        # 关键不变量：authorization_code 即便 _verify_mfa 会要求 MFA，也直接放行
        aux_user = _FakeUser("oauth")
        self.assertEqual(
            _authenticate(grant_type="authorization_code", aux=(True, aux_user),
                          aux_enable=True, mfa="MFA_REQUIRED"),
            (True, aux_user))

    def test_authorization_code_aux_disabled(self):
        self.assertEqual(_authenticate(grant_type="authorization_code", aux_enable=False),
                         (False, "认证失败"))

    def test_authorization_code_aux_failed(self):
        self.assertEqual(_authenticate(grant_type="authorization_code", aux=(False, "x"), aux_enable=True),
                         (False, "认证失败"))

    # ---- 不支持的类型 ----
    def test_unsupported_grant_type(self):
        self.assertEqual(_authenticate(grant_type="client_credentials"),
                         (False, "不支持的认证类型"))
