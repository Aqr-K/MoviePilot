import secrets
from typing import NamedTuple, Optional, Tuple, Union

from app.chain import ChainBase
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.db.models.user import User
from app.db.user_oper import UserOper
from app.log import logger
from app.schemas import AuthCredentials, AuthInterceptCredentials
from app.schemas.types import ChainEventType
from app.utils.otp import OtpUtils

PASSWORD_INVALID_CREDENTIALS_MESSAGE = "用户名或密码或二次校验码不正确"


class _AuthOutcome(NamedTuple):
    """user_authenticate 内部编排结果：user 非空表示已认证成功；apply_mfa 指明是否需走 MFA。"""
    user: Optional[User]
    error: Optional[str]
    apply_mfa: bool


class UserChain(ChainBase):
    """
    用户链，处理多种认证协议
    """

    def user_authenticate(
            self,
            username: Optional[str] = None,
            password: Optional[str] = None,
            mfa_code: Optional[str] = None,
            code: Optional[str] = None,
            grant_type: Optional[str] = "password"
    ) -> Union[Tuple[bool, Optional[str]], Tuple[bool, Optional[User]]]:
        """
        认证用户，根据不同的 grant_type 处理不同的认证流程

        :param username: 用户名，适用于 "password" grant_type
        :param password: 用户密码，适用于 "password" grant_type
        :param mfa_code: 一次性密码，适用于 "password" grant_type
        :param code: 授权码，适用于 "authorization_code" grant_type
        :param grant_type: 认证类型，如 "password", "authorization_code", "client_credentials"
        :return:
            - 对于成功的认证，返回 (True, User)
            - 对于失败的认证，返回 (False, "错误信息")
        """
        credentials = AuthCredentials(
            username=username,
            password=password,
            mfa_code=mfa_code,
            code=code,
            grant_type=grant_type
        )
        logger.debug(f"认证类型：{grant_type}，开始准备对用户 {username} 进行身份校验")
        # 1) 按 grant_type 解析出已认证用户（本地密码 → 辅助认证），并指明是否需走 MFA
        outcome = self._resolve_user(credentials)
        # 用 is None 而非真值判断：成功与否由 user 是否为 None 决定，避免未来 User 真值被覆写时误判
        if outcome.user is None:
            return False, outcome.error
        # 2) MFA 二次验证：仅 password grant 校验（authorization_code 等不校验，保持原行为）
        if outcome.apply_mfa:
            mfa_result = self._verify_mfa(outcome.user, credentials.mfa_code)
            if mfa_result == "MFA_REQUIRED":
                return False, "MFA_REQUIRED"
            if not mfa_result:
                return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE
        logger.info(f"用户 {username} 认证成功")
        return True, outcome.user

    def _resolve_user(self, credentials: AuthCredentials) -> _AuthOutcome:
        """
        按 grant_type 解析出已认证用户（不含 MFA），是 user_authenticate 的编排子步骤：
        - "password"：先本地密码，失败再辅助认证（若启用）；两条路得到的用户都需后续 MFA。
        - "authorization_code"：仅辅助认证（若启用），不走 MFA。
        - 其它：不支持。
        返回 _AuthOutcome(user, error, apply_mfa)：user 非空表示成功，否则 error 为失败信息。
        """
        grant_type = credentials.grant_type
        if grant_type == "password":
            success, user_or_message = self.password_authenticate(credentials=credentials)
            if success:
                return _AuthOutcome(user_or_message, None, apply_mfa=True)
            # 用户不存在或密码错误 → 辅助认证兜底
            if not settings.AUXILIARY_AUTH_ENABLE:
                logger.debug(f"辅助认证未启用，用户 {credentials.username} 认证失败")
                return _AuthOutcome(None, PASSWORD_INVALID_CREDENTIALS_MESSAGE, apply_mfa=False)
            logger.warning("密码认证失败，尝试通过外部服务进行辅助认证 ...")
            aux_success, aux_user_or_message = self.auxiliary_authenticate(credentials=credentials)
            if aux_success:
                return _AuthOutcome(aux_user_or_message, None, apply_mfa=True)
            return _AuthOutcome(None, PASSWORD_INVALID_CREDENTIALS_MESSAGE, apply_mfa=False)
        if grant_type == "authorization_code":
            if not settings.AUXILIARY_AUTH_ENABLE:
                return _AuthOutcome(None, "认证失败", apply_mfa=False)
            aux_success, aux_user_or_message = self.auxiliary_authenticate(credentials=credentials)
            if aux_success:
                return _AuthOutcome(aux_user_or_message, None, apply_mfa=False)
            return _AuthOutcome(None, "认证失败", apply_mfa=False)
        logger.debug(f"不支持的认证类型：{grant_type}")
        return _AuthOutcome(None, "不支持的认证类型", apply_mfa=False)

    @staticmethod
    def password_authenticate(credentials: AuthCredentials) -> Tuple[bool, Union[User, str]]:
        """
        密码认证

        :param credentials: 认证凭证，包含用户名、密码以及可选的 MFA 认证码
        :return:
            - 成功时返回 (True, User)，其中 User 是认证通过的用户对象
            - 失败时返回 (False, "错误信息")
        """
        if not credentials or credentials.grant_type != "password":
            logger.info("密码认证失败，认证类型不匹配")
            return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

        user = UserOper().get_by_name(name=credentials.username)
        if not user:
            logger.info(f"密码认证失败，用户 {credentials.username} 不存在")
            return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

        if not user.is_active:
            logger.info(f"密码认证失败，用户 {credentials.username} 已被禁用")
            return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

        if not verify_password(credentials.password, str(user.hashed_password)):
            logger.info(f"密码认证失败，用户 {credentials.username} 的密码验证不通过")
            return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

        return True, user

    def auxiliary_authenticate(self, credentials: AuthCredentials) -> Tuple[bool, Union[User, str]]:
        """
        辅助用户认证

        :param credentials: 认证凭证，包含必要的认证信息
        :return:
            - 成功时返回 (True, User)，其中 User 是认证通过的用户对象
            - 失败时返回 (False, "错误信息")
        """
        if not credentials:
            return False, "认证凭证无效"

        # 检查是否因为用户被禁用
        useroper = UserOper()
        if credentials.username:
            user = useroper.get_by_name(name=credentials.username)
            if user and not user.is_active:
                logger.info(f"用户 {user.name} 已被禁用，跳过后续身份校验")
                return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

        logger.debug(f"认证类型：{credentials.grant_type}，尝试通过系统模块进行辅助认证，用户: {credentials.username}")
        result = self.run_module("user_authenticate", credentials=credentials)

        if not result:
            logger.debug(f"通过系统模块辅助认证失败，尝试触发 {ChainEventType.AuthVerification} 事件")
            event = self.eventmanager.send_event(etype=ChainEventType.AuthVerification, data=credentials)
            if not event or not event.event_data:
                logger.error(f"认证类型：{credentials.grant_type}，辅助认证失败，未返回有效数据")
                return False, f"认证类型：{credentials.grant_type}，辅助认证事件失败或无效"

            credentials = event.event_data  # 使用事件返回的认证数据
        else:
            logger.info(f"通过系统模块辅助认证成功，用户: {credentials.username}")
            credentials = result  # 使用模块认证返回的认证数据

        # 处理认证成功的逻辑
        success = self._process_auth_success(username=credentials.username, credentials=credentials)
        if success:
            logger.info(f"用户 {credentials.username} 辅助认证通过")
            return True, useroper.get_by_name(credentials.username)
        else:
            logger.warning(f"用户 {credentials.username} 辅助认证未通过")
            return False, PASSWORD_INVALID_CREDENTIALS_MESSAGE

    @staticmethod
    def _verify_mfa(user: User, mfa_code: Optional[str]) -> Union[bool, str]:
        """
        验证 MFA（二次验证码）
        检查用户是否启用了 OTP 或 PassKey，如果启用了任何一种，都需要提供验证

        :param user: 用户对象
        :param mfa_code: 二次验证码（如果提供了则验证OTP）
        :return: 
            - 如果验证成功返回 True
            - 如果需要MFA但未提供，返回 "MFA_REQUIRED"
            - 如果MFA验证失败，返回 False
        """
        # 委托可插拔 MFA 因子注册表评估（PR3）：内建 OtpFactor + PasskeyFactor 绑定到当前 user，
        # evaluate_mfa 复现"OTP 优先 / PassKey 延后"语义；外部三值契约不变（由黄金矩阵守护）。
        from app.db.models.passkey import PassKey
        from app.core.auth.mfa_factors import MfaSubmission, MfaUserRef
        from app.service.auth.builtin_factors import build_builtin_factors
        from app.service.auth.orchestrator import evaluate_mfa

        factors = build_builtin_factors(
            is_otp_enrolled=lambda _ref: bool(user.is_otp),
            verify_otp=lambda _ref, code: OtpUtils.check(str(user.otp_secret), code),
            has_passkey=lambda _ref: bool(PassKey.get_by_user_id(db=None, user_id=user.id)),
        )
        result = evaluate_mfa(
            MfaUserRef(user_id=user.id, username=user.name),
            MfaSubmission(code=mfa_code),
            factors,
        )
        if result.kind == "mfa_required":
            logger.info(
                f"用户 {user.name} 已启用双重验证，需要提供验证码"
                f"（可用因子：{result.factors_available}）"
            )
            return "MFA_REQUIRED"
        if result.kind == "failure":
            logger.info(f"用户 {user.name} 的 MFA 认证失败")
            return False
        return True

    def _process_auth_success(self, username: str, credentials: AuthCredentials) -> bool:
        """
        处理辅助认证成功的逻辑，返回用户对象或创建新用户

        :param username: 用户名
        :param credentials: 认证凭证，包含 token、channel、service 等信息
        :return:
            - 如果认证成功并且用户存在或已创建，返回 User 对象
            - 如果认证被拦截或失败，返回 None
        """
        if not username:
            logger.info(f"未能获取到对应的用户信息，{credentials.grant_type} 认证不通过")
            return False

        token, channel, service = credentials.token, credentials.channel, credentials.service
        if not all([token, channel, service]):
            logger.info(f"用户 {username} 未通过 {credentials.grant_type} 认证，必要信息不足")
            return False

        # 触发认证通过的拦截事件
        intercept_event = self.eventmanager.send_event(
            etype=ChainEventType.AuthIntercept,
            data=AuthInterceptCredentials(username=username, channel=channel, service=service,
                                          token=token, status="completed")
        )
        if intercept_event and intercept_event.event_data:
            intercept_data: AuthInterceptCredentials = intercept_event.event_data
            if intercept_data.cancel:
                logger.warning(
                    f"认证被拦截，用户：{username}，渠道：{channel}，服务：{service}，拦截源：{intercept_data.source}")
                return False

        # 检查用户是否存在，如果不存在且当前为密码认证时则创建新用户
        useroper = UserOper()
        user = useroper.get_by_name(name=username)
        if user:
            # 如果用户存在，但是已经被禁用，则直接响应
            if not user.is_active:
                logger.info(f"辅助认证失败，用户 {username} 已被禁用")
                return False
            anonymized_token = f"{token[:len(token) // 2]}********"
            logger.info(
                f"认证类型：{credentials.grant_type}，用户：{username}，渠道：{channel}，"
                f"服务：{service} 认证成功，token：{anonymized_token}")
            return True
        else:
            if credentials.grant_type == "password":
                useroper.add(name=username, is_active=True, is_superuser=False,
                             hashed_password=get_password_hash(secrets.token_urlsafe(16)))
                logger.info(f"用户 {username} 不存在，已通过 {credentials.grant_type} 认证并已创建普通用户")
                return True
            else:
                logger.warning(
                    f"认证类型：{credentials.grant_type}，用户：{username}，渠道：{channel}，"
                    f"服务：{service} 认证不通过，未能在本地找到对应的用户信息")
                return False
