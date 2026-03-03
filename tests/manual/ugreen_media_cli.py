from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import uuid
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

# 兼容直接运行脚本：避免 app/utils 被放在 sys.path 首位导致标准库模块被同名文件遮蔽
if __name__ == "__main__" and __package__ is None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    if script_dir in sys.path:
        sys.path.remove(script_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

import requests

from app.utils.ugreen_crypto import UgreenCrypto


class UgreenLoginError(Exception):
    pass


def _normalize_base_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise UgreenLoginError("服务器地址不能为空")
    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    parsed = urlsplit(value)
    if not parsed.netloc:
        raise UgreenLoginError(f"无效服务器地址: {raw}")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def _json_or_raise(resp: requests.Response, stage: str) -> dict[str, Any]:
    try:
        data = resp.json()
    except Exception as exc:  # pragma: no cover - 网络异常路径
        raise UgreenLoginError(
            f"{stage} 返回非 JSON，HTTP {resp.status_code}，响应片段: {resp.text[:200]}"
        ) from exc
    if not isinstance(data, dict):
        raise UgreenLoginError(f"{stage} 返回格式异常: {type(data).__name__}")
    return data


def _decode_public_key(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise UgreenLoginError("未获取到公钥")
    if "BEGIN" in value:
        return value
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception as exc:
        raise UgreenLoginError("公钥解码失败") from exc


def _raise_if_failed(payload: Mapping[str, Any], stage: str) -> None:
    if payload.get("code") == 200:
        return
    raise UgreenLoginError(
        f"{stage}失败: code={payload.get('code')} msg={payload.get('msg')}"
    )


def _build_common_headers(
    client_id: str, client_version: str, language: str
) -> dict[str, str]:
    return {
        "Accept": "application/json, text/plain, */*",
        "Client-Id": client_id,
        "Client-Version": client_version,
        "UG-Agent": "PC/WEB",
        "X-Specify-Language": language,
    }


def _login_and_get_access(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
    keepalive: bool,
    headers: Mapping[str, str],
    timeout: float,
    verify_ssl: bool,
) -> tuple[str, str]:
    check_resp = session.post(
        f"{base_url}/ugreen/v1/verify/check",
        json={"username": username},
        headers=dict(headers),
        timeout=timeout,
        verify=verify_ssl,
    )
    check_json = _json_or_raise(check_resp, "获取登录公钥")
    _raise_if_failed(check_json, "获取登录公钥")

    rsa_token = (
        check_resp.headers.get("x-rsa-token")
        or check_resp.headers.get("X-Rsa-Token")
        or check_json.get("xRsaToken")
        or check_json.get("x-rsa-token")
    )
    if not rsa_token:
        data = check_json.get("data")
        if isinstance(data, Mapping):
            rsa_token = data.get("xRsaToken") or data.get("x-rsa-token")
    if not rsa_token:
        raise UgreenLoginError("登录公钥为空（x-rsa-token）")

    login_public_key = _decode_public_key(str(rsa_token))
    encrypted_password = UgreenCrypto(public_key=login_public_key).rsa_encrypt_long(
        password
    )

    login_payload = {
        "username": username,
        "password": encrypted_password,
        "keepalive": keepalive,
        "otp": True,
        "is_simple": True,
    }
    login_resp = session.post(
        f"{base_url}/ugreen/v1/verify/login",
        json=login_payload,
        headers=dict(headers),
        timeout=timeout,
        verify=verify_ssl,
    )
    login_json = _json_or_raise(login_resp, "登录")
    _raise_if_failed(login_json, "登录")

    data = login_json.get("data")
    if not isinstance(data, Mapping):
        raise UgreenLoginError("登录成功但响应 data 为空")

    token = str(data.get("token") or "").strip()
    public_key = str(data.get("public_key") or "").strip()
    if not token:
        raise UgreenLoginError("登录成功但未拿到 token")
    if not public_key:
        raise UgreenLoginError("登录成功但未拿到 public_key")
    return token, _decode_public_key(public_key)


def _fetch_media_lib(
    session: requests.Session,
    base_url: str,
    token: str,
    public_key: str,
    client_id: str,
    client_version: str,
    language: str,
    page: int,
    page_size: int,
    timeout: float,
    verify_ssl: bool,
) -> Any:
    crypto = UgreenCrypto(
        public_key=public_key,
        token=token,
        client_id=client_id,
        client_version=client_version,
        ug_agent="PC/WEB",
        language=language,
    )
    req = crypto.build_encrypted_request(
        url=f"{base_url}/ugreen/v1/video/homepage/media_list",
        method="GET",
        params={"page": page, "page_size": page_size},
    )
    media_resp = session.get(
        req.url,
        headers=req.headers,
        params=req.params,
        timeout=timeout,
        verify=verify_ssl,
    )
    media_json = _json_or_raise(media_resp, "获取媒体库")
    return crypto.decrypt_response(media_json, req.aes_key)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="登录绿联 NAS 并调用媒体库接口（自动处理请求加密/响应解密）"
    )
    parser.add_argument("--host", help="服务器地址，例如: http://192.168.20.101:9999")
    parser.add_argument("--username", help="用户名")
    parser.add_argument("--password", help="密码（不传则交互输入）")
    parser.add_argument("--client-id", help="可选，默认自动生成 UUID-WEB")
    parser.add_argument("--client-version", default="76363", help="默认: 76363")
    parser.add_argument("--language", default="zh-CN", help="默认: zh-CN")
    parser.add_argument("--page", type=int, default=1, help="默认: 1")
    parser.add_argument("--page-size", type=int, default=50, help="默认: 50")
    parser.add_argument("--timeout", type=float, default=20.0, help="默认: 20 秒")
    parser.add_argument("--insecure", action="store_true", help="忽略 HTTPS 证书校验")
    parser.add_argument(
        "--no-keepalive",
        action="store_true",
        help="关闭保持登录（默认保持登录）",
    )
    parser.add_argument("--pretty", action="store_true", help="美化输出 JSON")
    parser.add_argument("--output", help="将解密后的结果写入文件")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    host = args.host or input("服务器地址: ").strip()
    username = args.username or input("用户名: ").strip()
    password = args.password or getpass.getpass("密码: ")
    client_id = (args.client_id or f"{uuid.uuid4()}-WEB").strip()
    keepalive = not args.no_keepalive
    verify_ssl = not args.insecure

    try:
        base_url = _normalize_base_url(host)
        if args.insecure:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

        session = requests.Session()
        headers = _build_common_headers(
            client_id=client_id,
            client_version=args.client_version,
            language=args.language,
        )

        token, public_key = _login_and_get_access(
            session=session,
            base_url=base_url,
            username=username,
            password=password,
            keepalive=keepalive,
            headers=headers,
            timeout=args.timeout,
            verify_ssl=verify_ssl,
        )
        decoded = _fetch_media_lib(
            session=session,
            base_url=base_url,
            token=token,
            public_key=public_key,
            client_id=client_id,
            client_version=args.client_version,
            language=args.language,
            page=args.page,
            page_size=args.page_size,
            timeout=args.timeout,
            verify_ssl=verify_ssl,
        )

        if isinstance(decoded, Mapping):
            if decoded.get("code") != 200:
                raise UgreenLoginError(
                    f"媒体库接口失败: code={decoded.get('code')} msg={decoded.get('msg')}"
                )
            media_count = None
            data = decoded.get("data")
            if isinstance(data, Mapping) and isinstance(data.get("media_lib_info_list"), list):
                media_count = len(data["media_lib_info_list"])
            print(
                f"调用成功: code={decoded.get('code')} msg={decoded.get('msg')} "
                f"media_lib_info_list={media_count}"
            )

        text = json.dumps(
            decoded,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            separators=(",", ":") if not args.pretty else None,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
                f.write("\n")
            print(f"解密结果已写入: {args.output}")
        else:
            print(text)
        return 0
    except UgreenLoginError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"网络错误: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
