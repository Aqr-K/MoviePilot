import hmac
import ipaddress
import socket
import time
from hashlib import sha256
from pathlib import Path
from typing import List, Optional, Set, Union
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from anyio import Path as AsyncPath

from app.core.config import settings
from app.log import logger


class SecurityUtils:
    _SIGNED_URL_PURPOSE = "image-proxy"
    _SIGNED_URL_EXPIRE_SECONDS = 86400

    @staticmethod
    def is_safe_path(base_path: Path, user_path: Path,
                     allowed_suffixes: Optional[Union[Set[str], List[str]]] = None) -> bool:
        """
        验证用户提供的路径是否在基准目录内，并检查文件类型是否合法，防止目录遍历攻击

        :param base_path: 基准目录，允许访问的根目录
        :param user_path: 用户提供的路径，需检查其是否位于基准目录内
        :param allowed_suffixes: 允许的文件后缀名集合，用于验证文件类型
        :return: 如果用户路径安全且位于基准目录内，且文件类型合法，返回 True；否则返回 False
        :raises Exception: 如果解析路径时发生错误，则捕获并记录异常
        """
        try:
            # resolve() 将相对路径转换为绝对路径，并处理符号链接和'..'
            base_path_resolved = base_path.resolve()
            user_path_resolved = user_path.resolve()

            # 检查用户路径是否在基准目录或基准目录的子目录内
            if base_path_resolved != user_path_resolved and base_path_resolved not in user_path_resolved.parents:
                return False

            if allowed_suffixes is not None:
                allowed_suffixes = set(allowed_suffixes)
                if user_path.suffix.lower() not in allowed_suffixes:
                    return False

            return True
        except Exception as e:
            logger.debug(f"Error occurred while validating paths: {e}")
            return False

    @staticmethod
    async def async_is_safe_path(base_path: AsyncPath, user_path: AsyncPath,
                                 allowed_suffixes: Optional[Union[Set[str], List[str]]] = None) -> bool:
        """
        异步验证用户提供的路径是否在基准目录内，并检查文件类型是否合法，防止目录遍历攻击

        :param base_path: 基准目录，允许访问的根目录
        :param user_path: 用户提供的路径，需检查其是否位于基准目录内
        :param allowed_suffixes: 允许的文件后缀名集合，用于验证文件类型
        :return: 如果用户路径安全且位于基准目录内，且文件类型合法，返回 True；否则返回 False
        :raises Exception: 如果解析路径时发生错误，则捕获并记录异常
        """
        try:
            # resolve() 将相对路径转换为绝对路径，并处理符号链接和'..'
            base_path_resolved = await base_path.resolve()
            user_path_resolved = await user_path.resolve()

            # 检查用户路径是否在基准目录或基准目录的子目录内
            if base_path_resolved != user_path_resolved and base_path_resolved not in user_path_resolved.parents:
                return False

            if allowed_suffixes is not None:
                allowed_suffixes = set(allowed_suffixes)
                if user_path.suffix.lower() not in allowed_suffixes:
                    return False

            return True
        except Exception as e:
            logger.debug(f"Error occurred while validating paths: {e}")
            return False

    @staticmethod
    def _is_global_hostname(hostname: str) -> bool:
        """
        判断主机名解析结果是否全部为公网地址。

        图片代理会访问用户可控的 URL，这里必须在 allowlist 命中前后都排除
        私有、回环、链路本地、保留地址等非公网目标，避免通过 DNS 或字面量 IP
        绕过域名白名单访问内网服务。
        """
        if not hostname:
            return False
        try:
            return ipaddress.ip_address(hostname).is_global
        except ValueError:
            pass

        try:
            address_infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False

        if not address_infos:
            return False

        for address_info in address_infos:
            try:
                address = ipaddress.ip_address(address_info[4][0])
            except ValueError:
                return False
            if not address.is_global:
                return False
        return True

    @staticmethod
    def _url_signature_payload(url: str, expires_at: int, purpose: str) -> bytes:
        """
        构造 URL 签名载荷。

        签名覆盖用途、过期时间和完整 URL，确保同一个签名不能挪用到其它
        内网地址或其它代理用途。
        """
        return f"{purpose}\n{expires_at}\n{url}".encode("utf-8")

    @staticmethod
    def _sign_url_payload(url: str, expires_at: int, purpose: str) -> str:
        """
        使用 RESOURCE_SECRET_KEY 对 URL 签名载荷生成 HMAC。
        """
        return hmac.new(
            settings.RESOURCE_SECRET_KEY.encode("utf-8"),
            SecurityUtils._url_signature_payload(url, expires_at, purpose),
            sha256,
        ).hexdigest()

    @staticmethod
    def strip_url_signature(url: str) -> str:
        """
        移除 URL fragment 中的代理签名信息，得到真正要请求的地址。

        图片代理签名放在 fragment 中，浏览器会把它传给 MoviePilot，但 HTTP
        客户端请求媒体服务器前不能把这些内部参数带过去。
        """
        if not url:
            return url
        parsed_url = urlparse(url)
        return urlunparse(parsed_url._replace(fragment=""))

    @staticmethod
    def sign_url(
        url: str,
        expires_in: int = _SIGNED_URL_EXPIRE_SECONDS,
        purpose: str = _SIGNED_URL_PURPOSE,
    ) -> str:
        """
        给服务端返回的资源 URL 添加临时签名。

        该签名用于允许 `/system/img` 代理访问服务端已经确认过的私网图片 URL，
        避免代理端点重新依赖媒体服务器的具体路径规则。
        """
        if not url:
            return url
        parsed_url = urlparse(url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            return url
        clean_url = SecurityUtils.strip_url_signature(url)
        expires_at = int(time.time() + expires_in)
        signature = SecurityUtils._sign_url_payload(clean_url, expires_at, purpose)
        fragment = urlencode(
            {
                "mp_exp": str(expires_at),
                "mp_sig": signature,
                "mp_purpose": purpose,
            }
        )
        return urlunparse(urlparse(clean_url)._replace(fragment=fragment))

    @staticmethod
    def verify_signed_url(
        url: str,
        purpose: str = _SIGNED_URL_PURPOSE,
    ) -> Optional[str]:
        """
        验证 URL fragment 中的代理签名，成功时返回去签名后的真实 URL。
        """
        if not url:
            return None
        parsed_url = urlparse(url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            return None
        fragment_params = dict(parse_qsl(parsed_url.fragment, keep_blank_values=True))
        expires_at = fragment_params.get("mp_exp")
        signature = fragment_params.get("mp_sig")
        signed_purpose = fragment_params.get("mp_purpose")
        if not expires_at or not signature or signed_purpose != purpose:
            return None
        try:
            expires_at_int = int(expires_at)
        except ValueError:
            return None
        if expires_at_int < int(time.time()):
            return None

        clean_url = SecurityUtils.strip_url_signature(url)
        expected_signature = SecurityUtils._sign_url_payload(
            clean_url, expires_at_int, purpose
        )
        if not hmac.compare_digest(signature, expected_signature):
            return None
        return clean_url

    @staticmethod
    def is_safe_url(
        url: str,
        allowed_domains: Union[Set[str], List[str]],
        strict: bool = False,
        block_private: bool = False,
    ) -> bool:
        """
        验证URL是否在允许的域名列表中，包括带有端口的域名

        :param url: 需要验证的 URL
        :param allowed_domains: 允许的域名集合，域名可以包含端口
        :param strict: 是否严格匹配一级域名（默认为 False，允许多级域名）
        :param block_private: 是否拦截解析到非公网地址的 URL，防止 SSRF
        :return: 如果URL合法且在允许的域名列表中，返回 True；否则返回 False
        """
        try:
            # 解析URL
            parsed_url = urlparse(url)

            # 如果 URL 没有包含有效的 scheme，或者无法从中提取到有效的 netloc，则认为该 URL 是无效的
            if not parsed_url.scheme or not parsed_url.netloc:
                return False

            # 仅允许 http 或 https 协议
            if parsed_url.scheme not in {"http", "https"}:
                return False

            # 获取完整的 netloc（包括 IP 和端口）并转换为小写
            netloc = parsed_url.netloc.lower()
            if not netloc:
                return False

            if block_private and not SecurityUtils._is_global_hostname(parsed_url.hostname or ""):
                return False

            # 检查每个允许的域名
            allowed_domains = {d.lower() for d in allowed_domains}
            for domain in allowed_domains:
                parsed_allowed_url = urlparse(domain)
                allowed_netloc = parsed_allowed_url.netloc or parsed_allowed_url.path

                if strict:
                    # 严格模式下，要求完全匹配域名和端口
                    if netloc == allowed_netloc:
                        return True
                else:
                    # 非严格模式下，允许子域名匹配
                    if netloc == allowed_netloc or netloc.endswith('.' + allowed_netloc):
                        return True

            return False
        except Exception as e:
            logger.debug(f"Error occurred while validating URL: {e}")
            return False

    @staticmethod
    def sanitize_url_path(url: str, max_length: int = 120) -> str:
        """
        将 URL 的路径部分进行编码，确保合法字符，并对路径长度进行压缩处理（如果超出最大长度）

        :param url: 需要处理的 URL
        :param max_length: 路径允许的最大长度，超出时进行压缩
        :return: 处理后的路径字符串
        """
        # 解析 URL，获取路径部分
        parsed_url = urlparse(url)
        path = parsed_url.path.lstrip("/")

        # 对路径中的特殊字符进行编码
        safe_path = quote(path)

        # 如果路径过长，进行压缩处理
        if len(safe_path) > max_length:
            # 使用 SHA-256 对路径进行哈希，取前 16 位作为压缩后的路径
            hash_value = sha256(safe_path.encode()).hexdigest()[:16]
            # 使用哈希值代替过长的路径，同时保留文件扩展名
            file_extension = Path(safe_path).suffix.lower() if Path(safe_path).suffix else ""
            safe_path = f"compressed_{hash_value}{file_extension}"

        return safe_path
