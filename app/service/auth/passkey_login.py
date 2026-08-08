# -*- coding: utf-8 -*-
"""
通行密钥（WebAuthn）登录的框架无关共享逻辑（单一来源；不依赖 fastapi / HTTPException）。

收口两段纯逻辑供新登录流程步骤与既有登录端点共用：
  - ``begin_passkey_login`` ：生成认证选项与挑战；
  - ``verify_passkey_login``：校验断言并解析本地用户。
挑战态由 ``PasskeyChallengeStore`` 落服务端（TTL + 取即销毁），键空间独立于 SSO 的 CSRF state。
"""
from typing import Optional, Tuple

from app.core.challenge_store import ChallengeStore
from app.helper.passkey import PassKeyHelper
from app.service.mfa import build_credential_list

# 通行密钥登录挑战有效期（秒）：服务端短时存储，过期即重新发起登录
_CHALLENGE_TTL_SECONDS = 300


class PasskeyLoginError(Exception):
    """通行密钥登录领域异常：凭证无效 / 用户无效 / 断言校验失败。"""


class PasskeyChallengeStore:
    """通行密钥登录挑战的服务端短时存储（TTL + 取即销毁），键空间独立于 SSO CSRF state。"""

    def __init__(self, ttl_seconds: int = _CHALLENGE_TTL_SECONDS) -> None:
        """
        初始化挑战存储。

        :param ttl_seconds: 挑战有效期秒数
        """
        self._store = ChallengeStore(ttl_seconds=ttl_seconds)

    def issue(self, key: str, challenge: str) -> None:
        """
        登记一条挑战，键由调用方提供（流程令牌或挑战自身）。

        :param key: 存储键
        :param challenge: WebAuthn 挑战串
        :return: 无
        """
        self._store.put(key, {"challenge": challenge})

    def consume(self, key: str) -> Optional[str]:
        """
        取用并销毁一条未过期挑战（单次有效）。

        :param key: 存储键
        :return: 挑战串；不存在 / 过期 / 已用返回 None
        """
        payload = self._store.consume(key)
        return payload.get("challenge") if payload else None


# 模块级单例：登录流程步骤与登录端点共用同一存储（键空间不同，互不干扰）
passkey_challenge_store = PasskeyChallengeStore()


def begin_passkey_login(username: Optional[str] = None) -> Tuple[str, str]:
    """
    生成通行密钥登录认证选项与挑战。

    :param username: 用户名；为空走 usernameless（discoverable credential），不限定凭证；
        给定则限定该用户已注册的凭证
    :return: (options_json, challenge)
    :raises PasskeyLoginError: 指定用户名却查无用户或无凭证
    """
    from app.db.models.passkey import PassKey
    from app.db.models.user import User

    existing_credentials = None
    if username:
        user = User.get_by_name(db=None, name=username)
        existing_passkeys = (
            PassKey.get_by_user_id(db=None, user_id=user.id) if user else None
        )
        if not user or not existing_passkeys:
            raise PasskeyLoginError("认证失败")
        existing_credentials = build_credential_list(existing_passkeys)

    return PassKeyHelper.generate_authentication_options(
        existing_credentials=existing_credentials
    )


def verify_passkey_login(credential: dict, expected_challenge: str) -> "object":
    """
    校验通行密钥登录断言并更新使用记录，返回校验通过的本地用户。

    :param credential: 客户端 WebAuthn 断言
    :param expected_challenge: 服务端签发的期望挑战
    :return: 校验通过的本地 User
    :raises PasskeyLoginError: 凭证无效 / 用户无效或禁用 / 断言校验失败
    """
    from app.db.models.passkey import PassKey
    from app.db.models.user import User

    credential_id_raw = credential.get("id") or credential.get("rawId")
    if not credential_id_raw:
        raise PasskeyLoginError("无效的凭证")
    credential_id = PassKeyHelper.standardize_credential_id(credential_id_raw)

    passkey = PassKey.get_by_credential_id(db=None, credential_id=credential_id)
    user = User.get_by_id(db=None, user_id=passkey.user_id) if passkey else None
    if not passkey or not user or not user.is_active:
        raise PasskeyLoginError("认证失败")

    success, new_sign_count = PassKeyHelper.verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        credential_public_key=passkey.public_key,
        credential_current_sign_count=passkey.sign_count,
    )
    if not success:
        raise PasskeyLoginError("认证失败")

    passkey.update_last_used(db=None, sign_count=new_sign_count)
    return user
