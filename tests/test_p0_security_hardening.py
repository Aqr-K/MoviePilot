# -*- coding: utf-8 -*-
"""P0 安全加固回归测试。

覆盖：
- CORS 凭证与通配源不可共存：ALLOWED_HOSTS 含 '*' 时 allow_credentials 必须为 False。
- 认证限流器统一：/access-token 与 /auth/flow 共用同一限流器实例（预算不翻倍）。
- XFF/反代信任：settings 暴露 FORWARDED_ALLOW_IPS（默认仅信任本机）。
"""
from app.core.config import settings


class TestCorsCredentials:
    def test_wildcard_origin_disables_credentials(self):
        from app.factory import _cors_allow_credentials
        assert _cors_allow_credentials(["*"]) is False
        assert _cors_allow_credentials(["http://a", "*"]) is False

    def test_specific_origins_allow_credentials(self):
        from app.factory import _cors_allow_credentials
        assert _cors_allow_credentials(["https://app.example.com"]) is True
        assert _cors_allow_credentials([]) is True

    def test_app_middleware_reflects_helper(self):
        # 默认 ALLOWED_HOSTS=["*"] → 应用实际不声明 credentials
        from app.factory import _cors_allow_credentials
        assert _cors_allow_credentials(settings.ALLOWED_HOSTS) == ("*" not in settings.ALLOWED_HOSTS)


class TestAuthRateLimiterUnified:
    def test_access_token_and_flow_share_one_limiter(self):
        from app.core.auth_rate_limit import auth_rate_limiter
        from app.api.endpoints import login as login_mod
        from app.api.endpoints import auth as auth_mod
        # 三者必须是同一对象 → 同 ip:username 的暴破预算不被翻倍
        assert login_mod._auth_rate_limiter is auth_rate_limiter
        assert auth_mod._auth_advance_rate_limiter is auth_rate_limiter
        assert login_mod._auth_rate_limiter is auth_mod._auth_advance_rate_limiter


class TestForwardedAllowIps:
    def test_setting_exists_with_safe_default(self):
        assert hasattr(settings, "FORWARDED_ALLOW_IPS")
        assert isinstance(settings.FORWARDED_ALLOW_IPS, str)
        # 默认不应为通配（不可信网络下会被伪造 XFF 绕过限流）
        assert settings.FORWARDED_ALLOW_IPS != "*"
