import socket
from unittest import TestCase
from unittest.mock import patch

from app.utils.security import SecurityUtils


class SecurityUtilsTest(TestCase):

    def test_is_safe_url_keeps_default_allowlist_behavior(self):
        """
        默认 URL 校验保持历史 allowlist 行为，避免影响非代理调用方。
        """
        self.assertTrue(
            SecurityUtils.is_safe_url(
                "http://192.168.1.50:8096/secret.png",
                {"http://192.168.1.50:8096"},
            )
        )

    def test_is_safe_url_blocks_private_literal_ip_when_enabled(self):
        """
        启用 SSRF 防护时，即使内网 IP 命中 allowlist 也不能放行。
        """
        self.assertFalse(
            SecurityUtils.is_safe_url(
                "http://192.168.1.50:8096/secret.png",
                {"http://192.168.1.50:8096"},
                block_private=True,
            )
        )

    def test_is_safe_url_blocks_loopback_dns_result_when_enabled(self):
        """
        主机名解析到回环地址时必须拒绝，防止通过域名绕过内网地址拦截。
        """
        with patch(
            "app.utils.security.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("127.0.0.1", 0),
                )
            ],
        ):
            self.assertFalse(
                SecurityUtils.is_safe_url(
                    "http://internal.example.com/secret.png",
                    {"example.com"},
                    block_private=True,
                )
            )

    def test_is_safe_url_blocks_mixed_public_and_private_dns_results(self):
        """
        同一域名只要存在任一非公网解析结果，就不能作为图片代理目标。
        """
        with patch(
            "app.utils.security.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 0),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("10.0.0.8", 0),
                ),
            ],
        ):
            self.assertFalse(
                SecurityUtils.is_safe_url(
                    "https://assets.example.com/poster.jpg",
                    {"example.com"},
                    block_private=True,
                )
            )

    def test_is_safe_url_allows_public_dns_result_when_enabled(self):
        """
        域名解析结果全部为公网地址且命中 allowlist 时继续允许访问。
        """
        with patch(
            "app.utils.security.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 0),
                )
            ],
        ):
            self.assertTrue(
                SecurityUtils.is_safe_url(
                    "https://assets.example.com/poster.jpg",
                    {"example.com"},
                    block_private=True,
                )
            )

    def test_is_safe_url_rejects_dns_resolution_failure_when_enabled(self):
        """
        SSRF 防护无法确认目标地址时按失败处理，避免解析异常时继续请求。
        """
        with patch(
            "app.utils.security.socket.getaddrinfo",
            side_effect=socket.gaierror,
        ):
            self.assertFalse(
                SecurityUtils.is_safe_url(
                    "https://assets.example.com/poster.jpg",
                    {"example.com"},
                    block_private=True,
                )
            )
