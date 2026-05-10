import base64
import hashlib
import json
import mimetypes
import os
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from app.core.cache import FileCache
from app.core.config import settings
from app.core.context import Context, MediaInfo
from app.core.meta import MetaBase
from app.core.metainfo import MetaInfo
from app.log import logger
from app.utils.http import RequestUtils
from app.utils.string import StringUtils


@dataclass
class ILinkIncomingMessage:
    """iLink 归一化后的入站消息。"""

    user_id: str
    text: Optional[str] = None
    username: Optional[str] = None
    message_id: Optional[str] = None
    chat_id: Optional[str] = None
    context_token: Optional[str] = None
    images: List[Dict[str, Any]] = field(default_factory=list)
    audio_refs: List[str] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_message_payload(self) -> Dict[str, Any]:
        payload = {
            "__channel__": "wechatclawbot",
            "userid": self.user_id,
            "username": self.username or self.user_id,
            "text": self.text or "",
            "message_id": self.message_id,
            "chat_id": self.chat_id,
            "context_token": self.context_token,
            "images": self.images or None,
            "audio_refs": self.audio_refs or None,
            "files": self.files or None,
        }
        return {key: value for key, value in payload.items() if value is not None}


class ILinkClient:
    """iLink HTTP 客户端，负责二维码登录、消息发送与长轮询。"""

    channel_version = "1.0.2"
    cdn_base_url = "https://novac2c.cdn.weixin.qq.com/c2c"

    def __init__(
        self,
        base_url: str,
        bot_token: Optional[str] = None,
        account_id: Optional[str] = None,
        sync_buf: Optional[str] = None,
        timeout: int = 20,
        log_func: Optional[Callable[[str, str], None]] = None,
    ):
        self.base_url = (base_url or "https://ilinkai.weixin.qq.com").rstrip("/")
        self.bot_token = bot_token
        self.account_id = account_id
        self.sync_buf = sync_buf
        self.timeout = timeout
        self._log_func = log_func

    def _log(self, level: str, message: str) -> None:
        if self._log_func:
            try:
                self._log_func(level, f"[ILinkClient] {message}")
                return
            except Exception:
                pass

        text = f"[WechatClawBot][ILinkClient] {message}"
        level_value = (level or "info").lower()
        if level_value == "debug":
            logger.debug(text)
        elif level_value == "warning":
            logger.warning(text)
        elif level_value == "error":
            logger.error(text)
        else:
            logger.info(text)

    def set_credentials(
        self,
        bot_token: Optional[str],
        account_id: Optional[str] = None,
        sync_buf: Optional[str] = None,
    ) -> None:
        self.bot_token = bot_token
        self.account_id = account_id
        if sync_buf is not None:
            self.sync_buf = sync_buf

    def _headers(self, auth_required: bool = True) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "MoviePilot-WechatClawBot/1.0",
        }
        if auth_required and self.bot_token:
            headers["AuthorizationType"] = "ilink_bot_token"
            headers["Authorization"] = f"Bearer {self.bot_token}"
            headers["X-WECHAT-UIN"] = self._build_wechat_uin()
        return headers

    @staticmethod
    def _build_wechat_uin() -> str:
        random_u32 = random.getrandbits(32)
        return base64.b64encode(str(random_u32).encode("utf-8")).decode("ascii")

    def _with_base_info(self, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        payload = dict(body or {})
        base_info = payload.get("base_info")
        if not isinstance(base_info, dict):
            base_info = {}
        base_info.setdefault("channel_version", self.channel_version)
        payload["base_info"] = base_info
        return payload

    @staticmethod
    def _json(resp: Any) -> Dict[str, Any]:
        if not resp:
            return {}
        try:
            return resp.json() or {}
        except Exception:
            text = (getattr(resp, "text", "") or "").strip()
            if not text:
                return {}
            try:
                return json.loads(text)
            except Exception:
                return {}

    @staticmethod
    def _short_text(value: Any, max_len: int = 240) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, ensure_ascii=False)
            except Exception:
                text = str(value)
        else:
            text = str(value)
        text = text.replace("\n", " ").replace("\r", " ").strip()
        if len(text) > max_len:
            return f"{text[:max_len]}..."
        return text

    @staticmethod
    def _normalize_qrcode_url(value: Any) -> Optional[str]:
        """规范化二维码展示字段，兼容图片 URL、data URL 与裸 base64。"""
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None
        lowered = raw.lower()
        if lowered.startswith("data:image/"):
            return raw
        if lowered.startswith("//"):
            return f"https:{raw}"
        # 某些实现会直接返回二维码图片的 base64 内容，这里自动补齐 data URL 前缀
        if len(raw) >= 128 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", raw):
            return f"data:image/png;base64,{raw}"
        return raw

    @staticmethod
    def _pick_value(obj: Dict[str, Any], keys: List[str]) -> Optional[Any]:
        for key in keys:
            if key in obj and obj.get(key) not in (None, ""):
                return obj.get(key)
        return None

    @classmethod
    def _find_first_value(
        cls, data: Any, keys: List[str], max_depth: int = 5
    ) -> Optional[Any]:
        if max_depth < 0 or data is None:
            return None
        if isinstance(data, dict):
            direct = cls._pick_value(data, keys)
            if direct not in (None, ""):
                return direct
            for value in data.values():
                found = cls._find_first_value(value, keys, max_depth - 1)
                if found not in (None, ""):
                    return found
        elif isinstance(data, list):
            for value in data:
                found = cls._find_first_value(value, keys, max_depth - 1)
                if found not in (None, ""):
                    return found
        return None

    @classmethod
    def _find_first_list(
        cls, data: Any, prefer_keys: List[str], max_depth: int = 5
    ) -> Optional[List[Any]]:
        if max_depth < 0 or data is None:
            return None
        if isinstance(data, dict):
            for key in prefer_keys:
                value = data.get(key)
                if isinstance(value, list):
                    return value
            for value in data.values():
                found = cls._find_first_list(value, prefer_keys, max_depth - 1)
                if found is not None:
                    return found
        elif isinstance(data, list):
            if data and all(isinstance(item, dict) for item in data):
                return data
            for value in data:
                found = cls._find_first_list(value, prefer_keys, max_depth - 1)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _ok(payload: Dict[str, Any]) -> bool:
        if not payload:
            return False
        code = payload.get("errcode")
        if code is None:
            code = payload.get("code")
        if code is None:
            code = payload.get("ret")
        if code is None:
            err = payload.get("errmsg") or payload.get("error") or payload.get(
                "error_msg"
            )
            if err and str(err).strip().lower() not in {"ok", "success", "succeed"}:
                return False
            state = payload.get("status") or payload.get("state")
            if isinstance(state, str) and state.strip().lower() in {
                "error",
                "failed",
                "fail",
            }:
                return False
            return True
        try:
            return int(str(code)) == 0
        except Exception:
            return str(code).strip().lower() in {"0", "ok", "success", "succeed"}

    def _is_send_success(self, payload: Dict[str, Any]) -> bool:
        if not payload:
            return False
        code = self._find_first_value(
            payload, ["errcode", "code", "ret", "result_code", "status_code"]
        )
        if code is not None:
            try:
                return int(str(code)) == 0
            except Exception:
                return str(code).strip().lower() in {"0", "ok", "success", "succeed"}
        success_flag = self._find_first_value(
            payload, ["success", "ok", "is_success", "sent"]
        )
        if isinstance(success_flag, bool):
            return success_flag
        if success_flag is not None:
            if str(success_flag).strip().lower() in {
                "1",
                "true",
                "ok",
                "success",
                "succeed",
                "sent",
            }:
                return True
        state = self._find_first_value(payload, ["status", "state", "send_status"])
        if state is not None:
            if str(state).strip().lower() in {"ok", "success", "succeed", "sent", "done"}:
                return True
            if str(state).strip().lower() in {"failed", "error", "denied"}:
                return False
        err_text = self._find_first_value(payload, ["errmsg", "error", "error_msg", "detail"])
        if err_text is not None and str(err_text).strip():
            err_value = str(err_text).strip().lower()
            if err_value not in {"ok", "success", "succeed", "sent"}:
                return False
        return False

    def _is_send_explicit_failure(self, payload: Dict[str, Any]) -> bool:
        if not payload:
            return False
        code = self._find_first_value(
            payload, ["errcode", "code", "ret", "result_code", "status_code"]
        )
        if code is not None:
            try:
                return int(str(code)) != 0
            except Exception:
                return str(code).strip().lower() not in {"0", "ok", "success", "succeed"}
        success_flag = self._find_first_value(
            payload, ["success", "ok", "is_success", "sent"]
        )
        if isinstance(success_flag, bool):
            return not success_flag
        if success_flag is not None:
            if str(success_flag).strip().lower() in {
                "0",
                "false",
                "fail",
                "failed",
                "error",
                "denied",
            }:
                return True
        state = self._find_first_value(payload, ["status", "state", "send_status"])
        if state is not None:
            if str(state).strip().lower() in {
                "failed",
                "error",
                "denied",
                "forbidden",
                "blocked",
            }:
                return True
        err_text = self._find_first_value(payload, ["errmsg", "error", "error_msg", "detail"])
        if err_text is not None and str(err_text).strip():
            if str(err_text).strip().lower() not in {"ok", "success", "succeed", "sent"}:
                return True
        return False

    def _is_send_http_success(self, resp: Any, payload: Dict[str, Any]) -> bool:
        if resp is None:
            return False
        status_code = getattr(resp, "status_code", None)
        if status_code is None:
            return False
        try:
            status_ok = 200 <= int(status_code) < 300
        except Exception:
            status_ok = False
        if not status_ok:
            return False
        if not payload:
            return True
        return not self._is_send_explicit_failure(payload)

    @staticmethod
    def _build_user_candidates(to_user: str) -> List[str]:
        raw = str(to_user or "").strip()
        if not raw:
            return []
        candidates = [raw]
        if "@" in raw:
            candidates.append(raw.split("@", 1)[0])
        if raw.endswith("@im.wechat"):
            candidates.append(raw[: -len("@im.wechat")])
        else:
            candidates.append(f"{raw}@im.wechat")
        uniq: List[str] = []
        for item in candidates:
            value = str(item or "").strip()
            if value and value not in uniq:
                uniq.append(value)
        return uniq

    @staticmethod
    def _build_text_payloads(user_id: str, text: str) -> List[Dict[str, Any]]:
        return [
            {"to_user": user_id, "msg_type": "text", "text": {"content": text}},
            {"to_user": user_id, "msg_type": "text", "text": text},
            {"touser": user_id, "msgtype": "text", "text": {"content": text}},
            {"touser": user_id, "msgtype": "text", "text": text},
            {"to": user_id, "type": "text", "content": text},
            {"to_user_id": user_id, "msg_type": "text", "content": text},
        ]

    @staticmethod
    def _build_markdown_payloads(user_id: str, text: str) -> List[Dict[str, Any]]:
        return [
            {
                "to_user": user_id,
                "msg_type": "markdown",
                "markdown": {"content": text},
            },
            {
                "touser": user_id,
                "msgtype": "markdown",
                "markdown": {"content": text},
            },
            {"to": user_id, "type": "markdown", "content": text},
            {
                "to_user": user_id,
                "message_type": "markdown",
                "markdown": {"content": text},
            },
        ]

    @staticmethod
    def _aes_ecb_padded_size(plaintext_size: int) -> int:
        return ((int(plaintext_size) + 1 + 15) // 16) * 16

    @staticmethod
    def _encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, AES.block_size))

    @staticmethod
    def _encode_media_aes_key(aeskey: bytes) -> str:
        return base64.b64encode(aeskey.hex().encode("ascii")).decode("ascii")

    def _build_protocol_text_payload(
        self, user_id: str, text: str, context_token: Optional[str]
    ) -> Dict[str, Any]:
        msg = {
            "from_user_id": str(self.account_id or ""),
            "to_user_id": user_id,
            "client_id": f"mp-{uuid.uuid4()}",
            "message_type": 2,
            "message_state": 2,
            "item_list": [{"type": 1, "text_item": {"text": text}}],
        }
        if context_token:
            msg["context_token"] = context_token
        return {"msg": msg}

    def _build_protocol_image_payload(
        self,
        user_id: str,
        context_token: Optional[str],
        download_param: str,
        aeskey_b64: str,
        cipher_size: int,
    ) -> Dict[str, Any]:
        msg: Dict[str, Any] = {
            "from_user_id": str(self.account_id or ""),
            "to_user_id": user_id,
            "client_id": f"mp-{uuid.uuid4()}",
            "message_type": 2,
            "message_state": 2,
            "item_list": [
                {
                    "type": 2,
                    "image_item": {
                        "media": {
                            "encrypt_query_param": download_param,
                            "aes_key": aeskey_b64,
                            "encrypt_type": 1,
                        },
                        "mid_size": int(cipher_size),
                    },
                }
            ],
        }
        if context_token:
            msg["context_token"] = context_token
        return {"msg": msg}

    def _build_protocol_file_payloads(
        self,
        user_id: str,
        context_token: Optional[str],
        download_param: str,
        aeskey_b64: str,
        cipher_size: int,
        raw_size: int,
        file_name: str,
        mime_type: str,
        file_md5: str,
    ) -> List[Dict[str, Any]]:
        media = {
            "encrypt_query_param": download_param,
            "aes_key": aeskey_b64,
            "encrypt_type": 1,
        }
        file_item = {
            "name": file_name,
            "file_name": file_name,
            "filename": file_name,
            "title": file_name,
            "size": int(raw_size),
            "file_size": int(raw_size),
            "raw_size": int(raw_size),
            "mid_size": int(cipher_size),
            "mime_type": mime_type,
            "content_type": mime_type,
            "md5": file_md5,
            "media": media,
        }
        msg_base: Dict[str, Any] = {
            "from_user_id": str(self.account_id or ""),
            "to_user_id": user_id,
            "client_id": f"mp-{uuid.uuid4()}",
            "message_type": 2,
            "message_state": 2,
        }
        if context_token:
            msg_base["context_token"] = context_token
        protocol_candidates = []
        for item_type in (6, 5, 3):
            msg = dict(msg_base)
            msg["item_list"] = [{"type": item_type, "file_item": dict(file_item)}]
            protocol_candidates.append({"msg": msg})
        simple_candidates = [
            {
                "to_user": user_id,
                "msg_type": "file",
                "file": dict(file_item),
            },
            {
                "touser": user_id,
                "msgtype": "file",
                "file": dict(file_item),
            },
            {"to": user_id, "type": "file", "file": dict(file_item)},
        ]
        return [*protocol_candidates, *simple_candidates]

    def _request_upload_param(
        self,
        to_user: str,
        plaintext: bytes,
        media_types: Optional[List[int]] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[bytes], Optional[int], Optional[str]]:
        rawsize = len(plaintext)
        rawfilemd5 = hashlib.md5(plaintext).hexdigest()
        filesize = self._aes_ecb_padded_size(rawsize)
        filekey = os.urandom(16).hex()
        aeskey = os.urandom(16)
        last_payload = None
        media_type_candidates = media_types or [1]
        for media_type in media_type_candidates:
            body = self._with_base_info(
                {
                    "filekey": filekey,
                    "media_type": media_type,
                    "to_user_id": to_user,
                    "rawsize": rawsize,
                    "rawfilemd5": rawfilemd5,
                    "filesize": filesize,
                    "no_need_thumb": True,
                    "aeskey": aeskey.hex(),
                }
            )
            url = f"{self.base_url}/ilink/bot/getuploadurl"
            resp = RequestUtils(
                headers=self._headers(auth_required=True), timeout=self.timeout
            ).post(url, json=body)
            payload = self._json(resp)
            last_payload = payload or getattr(resp, "text", None)
            upload_param = (
                self._find_first_value(payload, ["upload_param", "uploadParam"])
                if payload
                else None
            )
            upload_full_url = (
                self._find_first_value(payload, ["upload_full_url", "uploadFullUrl", "full_url"])
                if payload
                else None
            )
            if upload_param or upload_full_url:
                return (
                    str(upload_param) if upload_param else None,
                    str(upload_full_url) if upload_full_url else None,
                    aeskey,
                    filesize,
                    filekey,
                )
        self._log(
            "warning",
            f"getuploadurl 失败: resp={self._short_text(last_payload)}",
        )
        return None, None, None, None, None

    def _upload_encrypted_to_cdn(
        self,
        upload_param: Optional[str],
        upload_full_url: Optional[str],
        filekey: str,
        plaintext: bytes,
        aeskey: bytes,
    ) -> Tuple[Optional[str], Optional[int]]:
        ciphertext = self._encrypt_aes_ecb(plaintext, aeskey)
        if upload_full_url:
            upload_url = str(upload_full_url).strip()
        elif upload_param:
            upload_url = (
                f"{self.cdn_base_url}/upload?encrypted_query_param={quote(str(upload_param), safe='')}&"
                f"filekey={quote(filekey, safe='')}"
            )
        else:
            self._log("warning", "CDN 上传失败: 缺少 upload_url 参数")
            return None, None
        resp = RequestUtils(
            headers={"Content-Type": "application/octet-stream"},
            timeout=self.timeout,
        ).post(upload_url, data=ciphertext)
        if getattr(resp, "status_code", None) != 200:
            self._log(
                "warning",
                f"CDN 上传失败: http={getattr(resp, 'status_code', None)}, err={self._short_text(getattr(resp, 'text', ''))}",
            )
            return None, None
        download_param = None
        if resp is not None and getattr(resp, "headers", None):
            download_param = resp.headers.get("x-encrypted-param")
        if not download_param:
            self._log("warning", "CDN 上传成功但缺少 x-encrypted-param")
            return None, None
        return str(download_param), len(ciphertext)

    def _send_payload_candidates(
        self,
        to_user: str,
        payload_candidates: List[Dict[str, Any]],
        url_candidates: Optional[List[str]] = None,
    ) -> bool:
        url_candidates = url_candidates or [
            f"{self.base_url}/ilink/bot/sendmessage",
            f"{self.base_url}/ilink/bot/sendmessage?bot_type=3",
        ]
        last_error = ""
        for user_id in self._build_user_candidates(to_user):
            for url in url_candidates:
                for index, body in enumerate(payload_candidates, start=1):
                    request_body = self._with_base_info(body)
                    resp = RequestUtils(
                        headers=self._headers(auth_required=True), timeout=self.timeout
                    ).post(url, json=request_body)
                    payload = self._json(resp)
                    if self._is_send_success(payload) or self._is_send_http_success(resp, payload):
                        self._log("info", f"发送消息成功: to_user={user_id}, variant={index}")
                        return True
                    http_code = getattr(resp, "status_code", None)
                    err_msg = (
                        self._find_first_value(payload, ["errmsg", "message", "error", "detail"])
                        if payload
                        else None
                    )
                    if not err_msg and resp is not None:
                        err_msg = self._short_text(getattr(resp, "text", ""))
                    last_error = f"http={http_code}, err={self._short_text(err_msg)}"
                    self._log(
                        "debug",
                        f"发送候选失败: to_user={user_id}, variant={index}, {last_error}, req={self._short_text(request_body)}, resp={self._short_text(payload)}",
                    )
        self._log("warning", f"发送消息失败: to_user={to_user}, {last_error}")
        return False

    def get_qrcode(self) -> Dict[str, Any]:
        url = f"{self.base_url}/ilink/bot/get_bot_qrcode?bot_type=3"
        self._log("debug", f"请求二维码: {url}")
        resp = RequestUtils(
            headers=self._headers(auth_required=False), timeout=self.timeout
        ).get_res(url)
        payload = self._json(resp)
        if not payload:
            return {"success": False, "message": "获取二维码失败"}
        data = payload.get("data") or payload.get("result") or payload
        qrcode = data.get("qrcode") or data.get("qr_code") or data.get(
            "qrcode_id"
        ) or data.get("ticket")
        qrcode_url = (
            data.get("qrcode_url")
            or data.get("url")
            or data.get("qrcodeUrl")
            or data.get("qr_url")
            or data.get("qrcode_img_content")
            or data.get("qrcode_img_url")
            or data.get("qr_img")
        )
        qrcode_url = self._normalize_qrcode_url(qrcode_url)
        if not qrcode_url and qrcode:
            qrcode_url = f"https://liteapp.weixin.qq.com/q/7GiQu1?qrcode={qrcode}&bot_type=3"
        return {
            "success": self._ok(payload) and bool(qrcode or qrcode_url),
            "qrcode": qrcode,
            "qrcode_url": qrcode_url,
            "raw": payload,
            "message": payload.get("errmsg") or payload.get("message"),
        }

    def get_qrcode_status(self, qrcode: str) -> Dict[str, Any]:
        url = f"{self.base_url}/ilink/bot/get_qrcode_status"
        resp = RequestUtils(
            headers=self._headers(auth_required=False), timeout=self.timeout
        ).get_res(url, params={"qrcode": qrcode})
        payload = self._json(resp)
        if not payload:
            retry_resp = RequestUtils(
                headers=self._headers(auth_required=False), timeout=self.timeout
            ).get_res(f"{url}?qrcode={qrcode}")
            payload = self._json(retry_resp)
        if not payload:
            return {
                "success": False,
                "status": "waiting",
                "token": None,
                "account_id": None,
                "raw": {},
                "message": "二维码状态接口返回空响应",
            }
        data = payload.get("data") or payload.get("result") or payload
        token = (
            data.get("bot_token")
            or data.get("token")
            or data.get("access_token")
            or self._find_first_value(
                data, ["bot_token", "access_token", "token", "jwt", "auth_token"]
            )
        )
        account_id = (
            data.get("account_id")
            or data.get("ilink_bot_id")
            or data.get("wxid")
            or data.get("uid")
            or data.get("user_id")
            or self._find_first_value(
                data,
                [
                    "account_id",
                    "ilink_bot_id",
                    "wxid",
                    "uid",
                    "user_id",
                    "from_user",
                    "from_uid",
                ],
            )
        )
        base_url = (
            data.get("baseurl")
            or data.get("base_url")
            or payload.get("baseurl")
            or payload.get("base_url")
        )
        if token:
            self.bot_token = token
        if account_id:
            self.account_id = str(account_id)
        state = (
            data.get("status")
            or data.get("state")
            or payload.get("status")
            or payload.get("state")
            or self._find_first_value(data, ["status", "state", "scan_status"])
            or "waiting"
        )
        return {
            "success": self._ok(payload),
            "status": str(state).lower(),
            "token": token,
            "account_id": account_id,
            "base_url": base_url,
            "qrcode_url": self._normalize_qrcode_url(
                data.get("qrcode_url")
                or data.get("url")
                or data.get("qrcodeUrl")
                or data.get("qr_url")
                or data.get("qrcode_img_content")
                or data.get("qrcode_img_url")
                or data.get("qr_img")
            ),
            "raw": payload,
            "message": payload.get("errmsg") or payload.get("message"),
        }

    def send_text(self, to_user: str, text: str, context_token: Optional[str] = None) -> bool:
        if not self.bot_token:
            self._log("warning", "发送消息失败：bot token 未配置")
            return False
        if not to_user or not text:
            self._log("warning", "发送消息失败：to_user 或 text 为空")
            return False
        payload_candidates = [
            self._build_protocol_text_payload(
                user_id=str(to_user), text=text, context_token=context_token
            ),
            *self._build_text_payloads(str(to_user), text),
        ]
        return self._send_payload_candidates(to_user=to_user, payload_candidates=payload_candidates)

    def send_markdown(
        self, to_user: str, text: str, context_token: Optional[str] = None
    ) -> bool:
        if not self.bot_token:
            self._log("warning", "发送 Markdown 失败：bot token 未配置")
            return False
        if not to_user or not text:
            self._log("warning", "发送 Markdown 失败：to_user 或 text 为空")
            return False
        payload_candidates = self._build_markdown_payloads(str(to_user), text)
        if self._send_payload_candidates(to_user=to_user, payload_candidates=payload_candidates):
            return True
        return self.send_text(to_user=to_user, text=text, context_token=context_token)

    def send_image_text_png(
        self,
        to_user: str,
        image_bytes: bytes,
        text: str,
        context_token: Optional[str] = None,
    ) -> bool:
        if not self.bot_token:
            self._log("warning", "发送图文失败：bot token 未配置")
            return False
        if not to_user or not image_bytes or not text:
            self._log("warning", "发送图文失败：to_user 或 image_bytes 或 text 为空")
            return False
        for user_id in self._build_user_candidates(to_user):
            upload_param, upload_full_url, aeskey, _, filekey = self._request_upload_param(
                user_id, image_bytes, media_types=[1]
            )
            if (not upload_param and not upload_full_url) or not aeskey or not filekey:
                continue
            download_param, cipher_size = self._upload_encrypted_to_cdn(
                upload_param=upload_param,
                upload_full_url=upload_full_url,
                filekey=filekey,
                plaintext=image_bytes,
                aeskey=aeskey,
            )
            if not download_param or not cipher_size:
                continue
            aeskey_b64 = self._encode_media_aes_key(aeskey)
            message_items = [
                {"type": 1, "text_item": {"text": text}},
                {
                    "type": 2,
                    "image_item": {
                        "media": {
                            "encrypt_query_param": download_param,
                            "aes_key": aeskey_b64,
                            "encrypt_type": 1,
                        },
                        "mid_size": int(cipher_size),
                    },
                },
            ]
            sent_all = True
            for item in message_items:
                msg = {
                    "from_user_id": str(self.account_id or ""),
                    "to_user_id": user_id,
                    "client_id": f"mp-{uuid.uuid4()}",
                    "message_type": 2,
                    "message_state": 2,
                    "item_list": [item],
                }
                if context_token:
                    msg["context_token"] = context_token
                if not self._send_payload_candidates(
                    to_user=user_id,
                    payload_candidates=[{"msg": msg}],
                ):
                    sent_all = False
                    break
            if sent_all:
                return True
        return False

    def send_image_png(
        self, to_user: str, image_bytes: bytes, context_token: Optional[str] = None
    ) -> bool:
        if not self.bot_token:
            self._log("warning", "发送图片失败：bot token 未配置")
            return False
        if not to_user or not image_bytes:
            self._log("warning", "发送图片失败：to_user 或 image_bytes 为空")
            return False
        for user_id in self._build_user_candidates(to_user):
            upload_param, upload_full_url, aeskey, _, filekey = self._request_upload_param(
                user_id, image_bytes, media_types=[1]
            )
            if (not upload_param and not upload_full_url) or not aeskey or not filekey:
                continue
            download_param, cipher_size = self._upload_encrypted_to_cdn(
                upload_param=upload_param,
                upload_full_url=upload_full_url,
                filekey=filekey,
                plaintext=image_bytes,
                aeskey=aeskey,
            )
            if not download_param or not cipher_size:
                continue
            aeskey_b64 = self._encode_media_aes_key(aeskey)
            body = self._build_protocol_image_payload(
                user_id=user_id,
                context_token=context_token,
                download_param=download_param,
                aeskey_b64=aeskey_b64,
                cipher_size=cipher_size,
            )
            if self._send_payload_candidates(
                to_user=user_id,
                payload_candidates=[body],
            ):
                return True
        return False

    def send_file_bytes(
        self,
        to_user: str,
        file_bytes: bytes,
        file_name: str,
        mime_type: str,
        context_token: Optional[str] = None,
    ) -> bool:
        if not self.bot_token:
            self._log("warning", "发送文件失败：bot token 未配置")
            return False
        if not to_user or not file_bytes:
            self._log("warning", "发送文件失败：to_user 或 file_bytes 为空")
            return False
        file_name = file_name or "attachment"
        mime_type = mime_type or "application/octet-stream"
        file_md5 = hashlib.md5(file_bytes).hexdigest()
        for user_id in self._build_user_candidates(to_user):
            upload_param, upload_full_url, aeskey, _, filekey = self._request_upload_param(
                user_id, file_bytes, media_types=[2, 6, 1]
            )
            if (not upload_param and not upload_full_url) or not aeskey or not filekey:
                continue
            download_param, cipher_size = self._upload_encrypted_to_cdn(
                upload_param=upload_param,
                upload_full_url=upload_full_url,
                filekey=filekey,
                plaintext=file_bytes,
                aeskey=aeskey,
            )
            if not download_param or not cipher_size:
                continue
            aeskey_b64 = self._encode_media_aes_key(aeskey)
            payload_candidates = self._build_protocol_file_payloads(
                user_id=user_id,
                context_token=context_token,
                download_param=download_param,
                aeskey_b64=aeskey_b64,
                cipher_size=cipher_size,
                raw_size=len(file_bytes),
                file_name=file_name,
                mime_type=mime_type,
                file_md5=file_md5,
            )
            if self._send_payload_candidates(
                to_user=user_id,
                payload_candidates=payload_candidates,
            ):
                return True
        return False

    @classmethod
    def _encode_ref_payload(cls, kind: str, payload: Dict[str, Any]) -> str:
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"wxclaw://{kind}/{encoded}"

    def _build_attachment_ref(
        self,
        kind: str,
        attachment: Dict[str, Any],
        default_name: Optional[str] = None,
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        if not isinstance(attachment, dict):
            return None
        download_url = (
            attachment.get("download_url")
            or attachment.get("url")
            or attachment.get("cdnurl")
            or attachment.get("cdn_url")
            or attachment.get("file_url")
        )
        if not download_url:
            return None
        payload = {
            "url": download_url,
            "aeskey": attachment.get("aeskey")
            or attachment.get("encoding_aes_key")
            or attachment.get("encrypt_key"),
            "encrypt_type": attachment.get("encrypt_type"),
            "mime_type": attachment.get("mime_type")
            or attachment.get("content_type"),
            "name": attachment.get("name")
            or attachment.get("filename")
            or default_name,
            "size": attachment.get("size") or attachment.get("file_size"),
        }
        ref = self._encode_ref_payload(kind=kind, payload=payload)
        return ref, payload

    @staticmethod
    def _as_scalar(value: Any) -> Optional[Any]:
        if value in (None, ""):
            return None
        if isinstance(value, (dict, list, tuple, set)):
            return None
        return value

    def _parse_incoming(self, item: Dict[str, Any]) -> Optional[ILinkIncomingMessage]:
        if not isinstance(item, dict):
            return None
        message = item
        for key in ["message", "msg", "event", "payload", "data", "body"]:
            child = item.get(key)
            if isinstance(child, dict):
                message = child
                break
        sender = (
            message.get("from")
            if isinstance(message.get("from"), dict)
            else message.get("sender")
            if isinstance(message.get("sender"), dict)
            else message.get("user")
            if isinstance(message.get("user"), dict)
            else message.get("from_user")
            if isinstance(message.get("from_user"), dict)
            else {}
        )
        user_id = (
            self._pick_value(sender, ["user_id", "id", "wxid", "uid"])
            or self._pick_value(
                message,
                [
                    "from_user",
                    "from_user_id",
                    "user_id",
                    "uid",
                    "wxid",
                    "from_uid",
                    "fromUser",
                    "fromUserId",
                    "openid",
                ],
            )
            or self._pick_value(
                item,
                [
                    "from_user",
                    "from_user_id",
                    "user_id",
                    "uid",
                    "wxid",
                    "from_uid",
                    "fromUser",
                    "fromUserId",
                    "openid",
                ],
            )
            or self._find_first_value(
                message,
                [
                    "from_user",
                    "from_user_id",
                    "user_id",
                    "sender_id",
                    "uid",
                    "wxid",
                    "from_uid",
                    "fromUserId",
                    "openid",
                ],
            )
        )
        user_id = self._as_scalar(user_id)
        if not user_id:
            return None
        username = (
            self._pick_value(sender, ["name", "nickname", "username", "remark"])
            or self._pick_value(
                message, ["username", "nickname", "from_name", "fromNick", "sender_name"]
            )
            or str(user_id)
        )
        message_id = self._pick_value(
            message, ["message_id", "msg_id", "id", "client_msg_id", "msgId"]
        ) or self._pick_value(item, ["message_id", "msg_id", "id", "client_msg_id", "msgId"])
        chat_id = self._pick_value(
            message,
            ["chat_id", "conversation_id", "room_id", "chatId", "conversationId", "roomId"],
        ) or self._pick_value(
            item,
            ["chat_id", "conversation_id", "room_id", "chatId", "conversationId", "roomId"],
        )
        context_token = self._pick_value(message, ["context_token", "contextToken"]) or self._pick_value(
            item, ["context_token", "contextToken"]
        )
        text_parts: List[str] = []
        images: List[Dict[str, Any]] = []
        audio_refs: List[str] = []
        files: List[Dict[str, Any]] = []

        def append_text(value: Any) -> None:
            if value in (None, ""):
                return
            if isinstance(value, dict):
                value = self._pick_value(value, ["content", "text", "value", "message"])
            if value in (None, ""):
                return
            text_value = str(value).strip()
            if text_value and text_value not in text_parts:
                text_parts.append(text_value)

        msgtype = str(
            message.get("msgtype") or message.get("msg_type") or message.get("type") or ""
        ).lower()
        if msgtype == "text":
            append_text((message.get("text") or {}).get("content") if isinstance(message.get("text"), dict) else None)
            append_text(message.get("content"))
        elif msgtype == "image":
            image_data = message.get("image") or {}
            image_ref = self._build_attachment_ref("image", image_data)
            if image_ref:
                ref, payload = image_ref
                images.append(
                    {
                        "ref": ref,
                        "name": payload.get("name"),
                        "mime_type": payload.get("mime_type"),
                        "size": payload.get("size"),
                    }
                )
        elif msgtype == "file":
            file_data = message.get("file") or {}
            file_ref = self._build_attachment_ref("file", file_data)
            if file_ref:
                ref, payload = file_ref
                files.append(
                    {
                        "ref": ref,
                        "name": payload.get("name"),
                        "mime_type": payload.get("mime_type"),
                        "size": payload.get("size"),
                    }
                )
        elif msgtype == "voice":
            voice_data = message.get("voice") or {}
            append_text((voice_data or {}).get("content"))
            voice_ref = self._build_attachment_ref("voice", voice_data, default_name="voice.amr")
            if voice_ref:
                ref, _ = voice_ref
                audio_refs.append(ref)
        elif msgtype == "mixed":
            for msg_item in ((message.get("mixed") or {}).get("msg_item") or []):
                item_type = str(msg_item.get("msgtype") or msg_item.get("type") or "").lower()
                if item_type == "text":
                    append_text((msg_item.get("text") or {}).get("content"))
                elif item_type == "image":
                    image_ref = self._build_attachment_ref("image", msg_item.get("image") or {})
                    if image_ref:
                        ref, payload = image_ref
                        images.append(
                            {
                                "ref": ref,
                                "name": payload.get("name"),
                                "mime_type": payload.get("mime_type"),
                                "size": payload.get("size"),
                            }
                        )
                elif item_type == "file":
                    file_ref = self._build_attachment_ref("file", msg_item.get("file") or {})
                    if file_ref:
                        ref, payload = file_ref
                        files.append(
                            {
                                "ref": ref,
                                "name": payload.get("name"),
                                "mime_type": payload.get("mime_type"),
                                "size": payload.get("size"),
                            }
                        )
                elif item_type == "voice":
                    append_text(((msg_item.get("voice") or {}).get("content") or "").strip())
                    voice_ref = self._build_attachment_ref(
                        "voice",
                        msg_item.get("voice") or {},
                        default_name="voice.amr",
                    )
                    if voice_ref:
                        ref, _ = voice_ref
                        audio_refs.append(ref)

        item_list = message.get("item_list") if isinstance(message.get("item_list"), list) else []
        for one in item_list:
            if not isinstance(one, dict):
                continue
            item_type = one.get("type")
            if item_type == 1 and isinstance(one.get("text_item"), dict):
                append_text((one.get("text_item") or {}).get("text"))
            elif item_type == 2 and isinstance(one.get("image_item"), dict):
                image_ref = self._build_attachment_ref(
                    "image", (one.get("image_item") or {}).get("media") or {}
                )
                if image_ref:
                    ref, payload = image_ref
                    images.append(
                        {
                            "ref": ref,
                            "name": payload.get("name"),
                            "mime_type": payload.get("mime_type"),
                            "size": payload.get("size"),
                        }
                    )
            elif item_type in {5, 6}:
                file_ref = self._build_attachment_ref(
                    "file", (one.get("file_item") or {}).get("media") or {}
                )
                if file_ref:
                    ref, payload = file_ref
                    files.append(
                        {
                            "ref": ref,
                            "name": (one.get("file_item") or {}).get("name")
                            or (one.get("file_item") or {}).get("file_name")
                            or payload.get("name"),
                            "mime_type": (one.get("file_item") or {}).get("mime_type")
                            or payload.get("mime_type"),
                            "size": (one.get("file_item") or {}).get("size")
                            or payload.get("size"),
                        }
                    )

        if not text_parts:
            append_text(
                self._pick_value(message, ["content", "message", "msg", "text", "body", "msg_content", "msgContent"])
            )
            append_text(
                self._pick_value(item, ["content", "message", "msg", "text", "body", "msg_content", "msgContent"])
            )
            append_text(self._find_first_value(message, ["content", "text", "message", "msg", "body", "cmd"]))

        text = "\n".join(part for part in text_parts if part).strip() or None
        return ILinkIncomingMessage(
            user_id=str(user_id),
            text=text,
            username=str(username) if username else None,
            message_id=str(message_id) if message_id else None,
            chat_id=str(chat_id) if chat_id else None,
            context_token=str(context_token) if context_token else None,
            images=images,
            audio_refs=audio_refs,
            files=files,
            raw=item,
        )

    def _extract_updates(
        self, payload: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        data = payload.get("data") or payload.get("result") or payload
        sync_buf = (
            data.get("get_updates_buf")
            or payload.get("get_updates_buf")
            or data.get("sync_buf")
            or data.get("syncBuf")
            or payload.get("sync_buf")
            or payload.get("syncBuf")
            or self._find_first_value(
                data,
                ["get_updates_buf", "sync_buf", "syncBuf", "cursor", "offset", "next_sync_buf"],
            )
        )
        list_keys = [
            "msgs",
            "updates",
            "messages",
            "items",
            "events",
            "msg_list",
            "msgList",
            "add_msgs",
            "addMsgs",
            "records",
            "list",
        ]
        candidates = [data.get(key) for key in list_keys] + [payload.get(key) for key in list_keys]
        for candidate in candidates:
            if isinstance(candidate, list):
                return candidate, sync_buf
        nested = self._find_first_list(data, prefer_keys=list_keys)
        if isinstance(nested, list):
            return nested, sync_buf
        if isinstance(data, list):
            return data, sync_buf
        if isinstance(data, dict):
            for key in ["message", "msg", "event", "item"]:
                item = data.get(key)
                if isinstance(item, dict):
                    return [item], sync_buf
        return [], sync_buf

    def poll_updates(
        self, timeout_seconds: int = 25
    ) -> Tuple[List[ILinkIncomingMessage], Optional[str], Dict[str, Any]]:
        if not self.bot_token:
            return [], self.sync_buf, {"success": False, "message": "bot token 未配置"}
        url = f"{self.base_url}/ilink/bot/getupdates"
        payload = {}
        body_candidates = [
            {"get_updates_buf": self.sync_buf or ""},
            {"sync_buf": self.sync_buf, "timeout": timeout_seconds},
            {"syncBuf": self.sync_buf, "timeout": timeout_seconds},
            {"sync_buf": self.sync_buf, "wait": timeout_seconds},
        ]
        for body in body_candidates:
            request_body = self._with_base_info(body)
            resp = RequestUtils(
                headers=self._headers(auth_required=True),
                timeout=timeout_seconds + 10,
            ).post(url, json=request_body)
            payload = self._json(resp)
            if payload and self._ok(payload):
                break
            if payload and self._find_first_list(
                payload, prefer_keys=["updates", "messages", "items", "events", "add_msgs", "msgs"]
            ):
                break
        if not payload:
            return [], self.sync_buf, {"success": False, "message": "轮询返回空响应"}
        items, sync_buf = self._extract_updates(payload)
        parsed: List[ILinkIncomingMessage] = []
        for item in items:
            message = self._parse_incoming(item)
            if message:
                parsed.append(message)
        if sync_buf is not None:
            self.sync_buf = str(sync_buf)
        return parsed, self.sync_buf, {
            "success": self._ok(payload),
            "raw": payload,
            "message": payload.get("errmsg") or payload.get("message"),
            "item_count": len(items),
            "parsed_count": len(parsed),
        }

    def test_connection(self) -> Tuple[bool, str]:
        if not self.bot_token:
            return False, "未登录，缺少 bot token"
        url = f"{self.base_url}/ilink/bot/getconfig"
        resp = RequestUtils(
            headers=self._headers(auth_required=True), timeout=self.timeout
        ).post(url, json={})
        payload = self._json(resp)
        if self._ok(payload):
            return True, "连接正常"
        return False, payload.get("errmsg") or payload.get("message") or "连接失败"


class WechatClawBot:
    """微信 ClawBot 渠道客户端。"""

    _default_base_url = "https://ilinkai.weixin.qq.com"
    _qrcode_ttl_seconds = 240
    _active_target_ttl_seconds = 24 * 60 * 60

    @classmethod
    def _build_cache_key(cls, config_name: str) -> str:
        safe_name = hashlib.md5(str(config_name or "wechatclawbot").encode("utf-8")).hexdigest()[:12]
        return f"__wechatclawbot_state_{safe_name}__"

    def __init__(
        self,
        WECHATCLAWBOT_BASE_URL: Optional[str] = None,
        WECHATCLAWBOT_DEFAULT_TARGET: Optional[str] = None,
        WECHATCLAWBOT_ADMINS: Optional[str] = None,
        WECHATCLAWBOT_POLL_TIMEOUT: Optional[int] = None,
        name: Optional[str] = None,
        auto_start_polling: bool = True,
        **kwargs,
    ):
        self._config_name = name or "wechatclawbot"
        self._base_url = (WECHATCLAWBOT_BASE_URL or self._default_base_url).rstrip("/")
        self._default_target = (WECHATCLAWBOT_DEFAULT_TARGET or "").strip() or None
        self._auto_start_polling = bool(auto_start_polling)
        self._admins = [
            admin.strip()
            for admin in str(WECHATCLAWBOT_ADMINS or "").split(",")
            if admin.strip()
        ]
        try:
            self._poll_timeout = max(10, int(WECHATCLAWBOT_POLL_TIMEOUT or 25))
        except Exception:
            self._poll_timeout = 25
        self._cache_key = self._build_cache_key(self._config_name)
        self._filecache = FileCache()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self._state = self._load_state()
        self._message_endpoint = (
            f"http://127.0.0.1:{settings.PORT}/api/v1/message?token={settings.API_TOKEN}&source={quote(self._config_name, safe='')}"
        )
        if self._state.get("bot_token") and self._auto_start_polling:
            self._start_polling()

    def _log(self, level: str, message: str) -> None:
        text = f"[WechatClawBot][{self._config_name}] {message}"
        level_value = (level or "info").lower()
        if level_value == "debug":
            logger.debug(text)
        elif level_value == "warning":
            logger.warning(text)
        elif level_value == "error":
            logger.error(text)
        else:
            logger.info(text)

    def _load_state(self) -> Dict[str, Any]:
        content = self._filecache.get(self._cache_key)
        if not content:
            return {
                "bot_token": None,
                "account_id": None,
                "sync_buf": None,
                "qrcode": {},
                "known_targets": {},
                "user_context_tokens": {},
                "base_url": self._base_url,
            }
        try:
            data = json.loads(content.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("invalid state")
            data.setdefault("qrcode", {})
            data.setdefault("known_targets", {})
            data.setdefault("user_context_tokens", {})
            data.setdefault("base_url", self._base_url)
            return data
        except Exception as err:
            self._log("warning", f"加载登录状态失败，已重置缓存：{err}")
            return {
                "bot_token": None,
                "account_id": None,
                "sync_buf": None,
                "qrcode": {},
                "known_targets": {},
                "user_context_tokens": {},
                "base_url": self._base_url,
            }

    def _save_state(self) -> None:
        self._state["base_url"] = self._base_url
        self._filecache.set(
            self._cache_key,
            json.dumps(self._state, ensure_ascii=False).encode("utf-8"),
        )

    def _build_client(self) -> ILinkClient:
        return ILinkClient(
            base_url=self._state.get("base_url") or self._base_url,
            bot_token=self._state.get("bot_token"),
            account_id=self._state.get("account_id"),
            sync_buf=self._state.get("sync_buf"),
            timeout=max(self._poll_timeout, 20),
            log_func=self._log,
        )

    def _update_state(self, **kwargs) -> None:
        with self._lock:
            self._state.update(kwargs)
            self._save_state()

    def _clear_login_state(self) -> None:
        with self._lock:
            self._state["bot_token"] = None
            self._state["account_id"] = None
            self._state["sync_buf"] = None
            self._state["user_context_tokens"] = {}
            self._save_state()

    def _qrcode_expired(self, updated_at: Optional[int]) -> bool:
        if not updated_at:
            return True
        return int(time.time()) - int(updated_at) > self._qrcode_ttl_seconds

    def _remember_target(
        self, user_id: str, username: Optional[str], context_token: Optional[str]
    ) -> None:
        if not user_id:
            return
        now_ts = int(time.time())
        with self._lock:
            known_targets = self._state.setdefault("known_targets", {})
            known_targets[str(user_id)] = {
                "username": username or str(user_id),
                "last_active": now_ts,
            }
            if context_token:
                tokens = self._state.setdefault("user_context_tokens", {})
                tokens[str(user_id)] = str(context_token)
            self._save_state()

    def _get_context_token(self, user_id: str) -> Optional[str]:
        tokens = self._state.get("user_context_tokens") or {}
        token = tokens.get(str(user_id))
        return str(token) if token else None

    def _get_targets(self, userid: Optional[str] = None) -> List[str]:
        if userid:
            return [str(userid)]
        if self._default_target:
            return [self._default_target]
        now_ts = int(time.time())
        known_targets = self._state.get("known_targets") or {}
        active_targets = [
            target
            for target, data in known_targets.items()
            if isinstance(data, dict)
            and now_ts - int(data.get("last_active") or 0) <= self._active_target_ttl_seconds
        ]
        if active_targets:
            return sorted(active_targets)
        return sorted(known_targets.keys())

    @staticmethod
    def _split_content(content: str, max_bytes: int = 3000) -> List[str]:
        if not content:
            return []
        chunks: List[str] = []
        current = bytearray()
        for line in content.splitlines():
            encoded = (line + "\n").encode("utf-8")
            if len(encoded) > max_bytes:
                if current:
                    chunks.append(current.decode("utf-8", errors="replace").strip())
                    current = bytearray()
                start = 0
                while start < len(encoded):
                    end = min(start + max_bytes, len(encoded))
                    while end > start and end < len(encoded) and (encoded[end] & 0xC0) == 0x80:
                        end -= 1
                    chunks.append(encoded[start:end].decode("utf-8", errors="replace").strip())
                    start = end
                continue
            if len(current) + len(encoded) > max_bytes:
                chunks.append(current.decode("utf-8", errors="replace").strip())
                current = bytearray()
            current += encoded
        if current:
            chunks.append(current.decode("utf-8", errors="replace").strip())
        return [chunk for chunk in chunks if chunk]

    @staticmethod
    def _compose_markdown(
        title: Optional[str] = None,
        text: Optional[str] = None,
        link: Optional[str] = None,
    ) -> str:
        parts = []
        if title:
            parts.append(f"## {title}")
        if text:
            parts.append(str(text).replace("\n\n", "\n"))
        if link:
            parts.append(f"查看详情：{link}")
        return "\n\n".join(part for part in parts if part).strip()

    @staticmethod
    def _guess_mime_type(file_path: Path, file_bytes: bytes) -> str:
        guessed = mimetypes.guess_type(file_path.name)[0]
        if guessed:
            return guessed
        if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if file_bytes.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if file_bytes.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        return "application/octet-stream"

    def _load_remote_image(self, image: str) -> Optional[bytes]:
        image_url = str(image or "").strip()
        if not image_url:
            return None
        if image_url.startswith("data:image/"):
            try:
                _, raw = image_url.split(",", 1)
                return base64.b64decode(raw)
            except Exception:
                return None
        if image_url.startswith("/"):
            image_url = settings.MP_DOMAIN(image_url)
        if not image_url.lower().startswith("http"):
            return None
        try:
            resp = RequestUtils(
                timeout=20,
                proxies=settings.PROXY,
                ua=settings.USER_AGENT,
            ).get_res(image_url)
            if resp and resp.status_code == 200 and resp.content:
                content_type = (resp.headers.get("Content-Type") or "").lower()
                if not content_type or "image" in content_type:
                    return resp.content
        except Exception as err:
            self._log("warning", f"加载图片失败：{err}")
        return None

    def get_state(self) -> bool:
        return bool(self._state.get("bot_token"))

    def stop(self) -> None:
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5)
        self._poll_thread = None

    def _start_polling(self) -> None:
        if not self._state.get("bot_token"):
            return
        if self._poll_thread and self._poll_thread.is_alive():
            return
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        self._log("info", "消息轮询线程已启动")

    def _poll_loop(self) -> None:
        consecutive_failures = 0
        backoff = [1, 2, 5, 10, 30]
        while not self._stop_event.is_set() and self._state.get("bot_token"):
            try:
                client = self._build_client()
                messages, sync_buf, result = client.poll_updates(
                    timeout_seconds=self._poll_timeout
                )
                if sync_buf is not None and sync_buf != self._state.get("sync_buf"):
                    self._update_state(sync_buf=sync_buf)
                if not result.get("success"):
                    raise RuntimeError(result.get("message") or "poll failed")
                for message in messages:
                    self._remember_target(
                        user_id=message.user_id,
                        username=message.username,
                        context_token=message.context_token,
                    )
                    try:
                        RequestUtils(timeout=15).post_res(
                            self._message_endpoint,
                            json=message.to_message_payload(),
                        )
                    except Exception as err:
                        self._log("error", f"转发微信 ClawBot 消息失败：{err}")
                consecutive_failures = 0
            except Exception as err:
                consecutive_failures += 1
                delay = backoff[min(consecutive_failures - 1, len(backoff) - 1)]
                self._log("warning", f"轮询异常，{delay}s 后重试：{err}")
                if consecutive_failures >= 10:
                    self._log("error", "轮询连续失败，已清理登录状态")
                    self._clear_login_state()
                    break
                self._stop_event.wait(delay)

    def _build_known_targets(self) -> List[Dict[str, Any]]:
        known_targets = self._state.get("known_targets") or {}
        items = []
        for userid, data in known_targets.items():
            if not isinstance(data, dict):
                continue
            items.append(
                {
                    "userid": userid,
                    "username": data.get("username") or userid,
                    "last_active": data.get("last_active"),
                }
            )
        return sorted(items, key=lambda item: item.get("last_active") or 0, reverse=True)

    def refresh_qrcode(self) -> Dict[str, Any]:
        if self._state.get("bot_token"):
            return self.get_status(refresh_remote=False)
        client = ILinkClient(base_url=self._base_url, timeout=max(self._poll_timeout, 20), log_func=self._log)
        result = client.get_qrcode()
        if not result.get("success"):
            return result
        qrcode = {
            "qrcode": result.get("qrcode"),
            "qrcode_url": result.get("qrcode_url"),
            "status": "waiting",
            "updated_at": int(time.time()),
        }
        self._update_state(qrcode=qrcode)
        return self.get_status(refresh_remote=False)

    def get_status(
        self,
        refresh_remote: bool = True,
        auto_generate_qrcode: bool = False,
    ) -> Dict[str, Any]:
        qrcode = self._state.get("qrcode") or {}
        if (
            auto_generate_qrcode
            and not self._state.get("bot_token")
            and (not qrcode.get("qrcode") or self._qrcode_expired(qrcode.get("updated_at")))
        ):
            self.refresh_qrcode()
            qrcode = self._state.get("qrcode") or {}
        if refresh_remote and not self._state.get("bot_token") and qrcode.get("qrcode"):
            client = ILinkClient(base_url=self._base_url, timeout=max(self._poll_timeout, 20), log_func=self._log)
            result = client.get_qrcode_status(str(qrcode.get("qrcode")))
            updated_qrcode = dict(qrcode)
            updated_qrcode["status"] = result.get("status") or updated_qrcode.get("status") or "waiting"
            updated_qrcode["updated_at"] = int(time.time())
            if result.get("qrcode_url"):
                updated_qrcode["qrcode_url"] = result.get("qrcode_url")
            update_payload: Dict[str, Any] = {"qrcode": updated_qrcode}
            if result.get("token"):
                update_payload.update(
                    {
                        "bot_token": result.get("token"),
                        "account_id": str(result.get("account_id") or "") or None,
                        "sync_buf": None,
                        "base_url": (result.get("base_url") or self._base_url).rstrip("/"),
                    }
                )
                self._base_url = (result.get("base_url") or self._base_url).rstrip("/")
                self._update_state(**update_payload)
                if self._auto_start_polling:
                    self._start_polling()
            else:
                self._update_state(**update_payload)
            qrcode = self._state.get("qrcode") or {}
        return {
            "success": True,
            "connected": bool(self._state.get("bot_token")),
            "account_id": self._state.get("account_id"),
            "qrcode": qrcode.get("qrcode"),
            "qrcode_url": qrcode.get("qrcode_url"),
            "qrcode_status": qrcode.get("status"),
            "qrcode_updated_at": qrcode.get("updated_at"),
            "known_targets": self._build_known_targets(),
            "default_target": self._default_target,
            "base_url": self._base_url,
        }

    def logout(self) -> Dict[str, Any]:
        self.stop()
        with self._lock:
            self._state["bot_token"] = None
            self._state["account_id"] = None
            self._state["sync_buf"] = None
            self._state["qrcode"] = {}
            self._state["user_context_tokens"] = {}
            self._save_state()
        return {"success": True, "message": "已退出微信 ClawBot 登录"}

    def test_connection(self) -> Tuple[bool, str]:
        if not self._state.get("bot_token"):
            return False, "未登录，请先扫码完成绑定"
        return self._build_client().test_connection()

    @classmethod
    def migrate_cached_state(
        cls,
        old_name: Optional[str],
        new_name: Optional[str],
        cleanup_old: bool = False,
        overwrite: bool = False,
    ) -> Tuple[bool, str]:
        """迁移配置重命名后的登录缓存，默认复制而不是删除旧缓存。"""
        source_name = str(old_name or "").strip()
        target_name = str(new_name or "").strip()
        if not source_name or not target_name:
            return False, "旧名称或新名称不能为空"
        if source_name == target_name:
            return True, "通知名称未变化，无需迁移登录缓存"

        cache = FileCache()
        source_key = cls._build_cache_key(source_name)
        target_key = cls._build_cache_key(target_name)
        source_state = cache.get(source_key)
        if not source_state:
            return True, "未找到可迁移的微信 ClawBot 登录缓存"
        if cache.exists(target_key) and not overwrite:
            return True, "新名称下已存在登录缓存，跳过迁移"

        cache.set(target_key, source_state)
        if cleanup_old:
            cache.delete(source_key)
        return True, f"已将微信 ClawBot 登录缓存从 {source_name} 迁移到 {target_name}"

    @staticmethod
    def _decode_ref_payload(ref: str, kind: str) -> Optional[Dict[str, Any]]:
        prefix = f"wxclaw://{kind}/"
        if not ref or not ref.startswith(prefix):
            return None
        encoded = ref.replace(prefix, "", 1)
        padding = "=" * (-len(encoded) % 4)
        try:
            return json.loads(
                base64.urlsafe_b64decode((encoded + padding).encode("ascii")).decode(
                    "utf-8"
                )
            )
        except Exception:
            return None

    @staticmethod
    def _decode_aes_key(aeskey: Optional[str]) -> Optional[bytes]:
        if not aeskey:
            return None
        value = str(aeskey).strip()
        if not value:
            return None
        if re.fullmatch(r"[0-9a-fA-F]{32}", value):
            try:
                return bytes.fromhex(value)
            except Exception:
                return None
        for candidate in (value, value + "=" * (-len(value) % 4)):
            try:
                decoded = base64.b64decode(candidate)
                if len(decoded) == 16:
                    return decoded
                if len(decoded) == 32 and re.fullmatch(rb"[0-9a-fA-F]{32}", decoded):
                    return bytes.fromhex(decoded.decode("ascii"))
            except Exception:
                continue
        return None

    @staticmethod
    def _unpad_bytes(content: bytes) -> Optional[bytes]:
        if not content:
            return None
        padding_len = content[-1]
        if padding_len <= 0 or padding_len > 16:
            return None
        if content[-padding_len:] != bytes([padding_len]) * padding_len:
            return None
        return content[:-padding_len]

    @classmethod
    def _decrypt_if_needed(
        cls,
        content: bytes,
        aeskey: Optional[str],
        mime_type: Optional[str] = None,
    ) -> bytes:
        aes_bytes = cls._decode_aes_key(aeskey)
        if not aes_bytes or not content:
            return content
        candidates = [content]
        try:
            candidates.append(AES.new(aes_bytes, AES.MODE_ECB).decrypt(content))
        except Exception:
            pass
        try:
            candidates.append(AES.new(aes_bytes, AES.MODE_CBC, aes_bytes[:16]).decrypt(content))
        except Exception:
            pass
        normalized_candidates: List[bytes] = []
        for candidate in candidates:
            normalized_candidates.append(candidate)
            unpadded = cls._unpad_bytes(candidate)
            if unpadded:
                normalized_candidates.append(unpadded)
        preferred_prefixes = []
        mime_value = (mime_type or "").lower()
        if mime_value.startswith("image/png"):
            preferred_prefixes.append(b"\x89PNG\r\n\x1a\n")
        elif mime_value.startswith("image/jpeg"):
            preferred_prefixes.append(b"\xff\xd8\xff")
        elif mime_value.startswith("image/gif"):
            preferred_prefixes.extend([b"GIF87a", b"GIF89a"])
        elif mime_value.startswith("audio/"):
            preferred_prefixes.extend([b"#!AMR", b"ID3", b"OggS", b"RIFF"])
        for candidate in normalized_candidates:
            if any(candidate.startswith(prefix) for prefix in preferred_prefixes):
                return candidate
        for candidate in normalized_candidates:
            if candidate.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"PK\x03\x04", b"#!AMR", b"ID3", b"OggS", b"RIFF")):
                return candidate
        return content

    @staticmethod
    def _guess_binary_mime(content: bytes, default: str = "application/octet-stream") -> str:
        if not content:
            return default
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if content.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if content.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if content.startswith(b"#!AMR"):
            return "audio/amr"
        if content.startswith(b"OggS"):
            return "audio/ogg"
        if content.startswith(b"ID3"):
            return "audio/mpeg"
        if content.startswith(b"RIFF") and b"WAVE" in content[:16]:
            return "audio/wav"
        if content.startswith(b"PK\x03\x04"):
            return "application/zip"
        return default

    def _download_ref_bytes(self, ref: str, kind: str) -> Optional[Tuple[bytes, str, Optional[str]]]:
        payload = self._decode_ref_payload(ref=ref, kind=kind)
        if not payload:
            return None
        download_url = payload.get("url")
        if not download_url:
            return None
        try:
            resp = RequestUtils(timeout=30).get_res(download_url)
        except Exception as err:
            self._log("error", f"下载 {kind} 失败：{err}")
            return None
        if not resp or not resp.content:
            return None
        content = self._decrypt_if_needed(
            content=resp.content,
            aeskey=payload.get("aeskey"),
            mime_type=payload.get("mime_type"),
        )
        mime_type = payload.get("mime_type") or self._guess_binary_mime(
            content,
            (resp.headers.get("Content-Type") or "application/octet-stream").split(
                ";", 1
            )[0],
        )
        return content, mime_type, payload.get("name")

    def download_image_to_data_url(self, image_ref: str) -> Optional[str]:
        result = self._download_ref_bytes(ref=image_ref, kind="image")
        if not result:
            return None
        content, mime_type, _ = result
        return f"data:{mime_type};base64,{base64.b64encode(content).decode()}"

    def download_media_bytes(self, media_ref: str) -> Optional[bytes]:
        kind = None
        if media_ref.startswith("wxclaw://file/"):
            kind = "file"
        elif media_ref.startswith("wxclaw://voice/"):
            kind = "voice"
        if not kind:
            return None
        result = self._download_ref_bytes(ref=media_ref, kind=kind)
        return result[0] if result else None

    def send_msg(
        self,
        title: str,
        text: Optional[str] = None,
        image: Optional[str] = None,
        userid: Optional[str] = None,
        link: Optional[str] = None,
        **kwargs,
    ) -> Optional[bool]:
        targets = self._get_targets(userid=userid)
        if not targets:
            self._log("warning", "未找到可发送的微信 ClawBot 目标")
            return False
        image_bytes = self._load_remote_image(image) if image else None
        content = self._compose_markdown(title=title, text=text, link=link)
        ok = False
        for target in targets:
            context_token = self._get_context_token(target)
            if image_bytes and content:
                sent = self._build_client().send_image_text_png(
                    to_user=target,
                    image_bytes=image_bytes,
                    text=content,
                    context_token=context_token,
                )
            elif image_bytes:
                sent = self._build_client().send_image_png(
                    to_user=target,
                    image_bytes=image_bytes,
                    context_token=context_token,
                )
            else:
                sent = True
                for chunk in self._split_content(content):
                    if not self._build_client().send_markdown(
                        to_user=target,
                        text=chunk,
                        context_token=context_token,
                    ):
                        sent = False
                        break
            ok = ok or bool(sent)
        return ok

    def send_file(
        self,
        file_path: str,
        file_name: Optional[str] = None,
        title: Optional[str] = None,
        text: Optional[str] = None,
        userid: Optional[str] = None,
        **kwargs,
    ) -> Optional[bool]:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            self._log("warning", f"待发送文件不存在：{file_path}")
            return False
        file_bytes = path.read_bytes()
        effective_name = file_name or path.name
        mime_type = self._guess_mime_type(path, file_bytes)
        targets = self._get_targets(userid=userid)
        if not targets:
            return False
        caption = self._compose_markdown(title=title, text=text)
        ok = False
        for target in targets:
            context_token = self._get_context_token(target)
            sent = True
            if caption:
                for chunk in self._split_content(caption):
                    if not self._build_client().send_markdown(
                        to_user=target,
                        text=chunk,
                        context_token=context_token,
                    ):
                        sent = False
                        break
            if sent:
                if mime_type.startswith("image/"):
                    sent = self._build_client().send_image_png(
                        to_user=target,
                        image_bytes=file_bytes,
                        context_token=context_token,
                    )
                else:
                    sent = self._build_client().send_file_bytes(
                        to_user=target,
                        file_bytes=file_bytes,
                        file_name=effective_name,
                        mime_type=mime_type,
                        context_token=context_token,
                    )
            ok = ok or bool(sent)
        return ok

    def send_medias_msg(
        self, medias: List[MediaInfo], userid: Optional[str] = None
    ) -> Optional[bool]:
        if not medias:
            return False
        lines = []
        for index, media in enumerate(medias, start=1):
            line = f"{index}. {media.title_year}"
            if media.vote_average:
                line += f" 评分：{media.vote_average}"
            if media.detail_link:
                line += f"\n{media.detail_link}"
            lines.append(line)
        return self.send_msg(title="媒体列表", text="\n\n".join(lines), userid=userid)

    def send_torrents_msg(
        self,
        torrents: List[Context],
        userid: Optional[str] = None,
        title: Optional[str] = None,
        link: Optional[str] = None,
    ) -> Optional[bool]:
        if not torrents:
            return False
        lines = []
        for index, context in enumerate(torrents, start=1):
            torrent = context.torrent_info
            meta = MetaInfo(title=torrent.title, subtitle=torrent.description)
            text = (
                f"{index}.【{torrent.site_name}】{meta.season_episode} {meta.resource_term} "
                f"{meta.video_term} {meta.release_group} {StringUtils.str_filesize(torrent.size)} "
                f"{torrent.volume_factor} {torrent.seeders}↑"
            )
            text = re.sub(r"\s+", " ", text).strip()
            if torrent.page_url:
                text += f"\n{torrent.page_url}"
            lines.append(text)
        return self.send_msg(
            title=title or "种子列表",
            text="\n\n".join(lines),
            userid=userid,
            link=link,
        )
