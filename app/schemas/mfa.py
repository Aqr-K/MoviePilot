# -*- coding: utf-8 -*-
from typing import Optional

from pydantic import BaseModel


class OtpVerifyRequest(BaseModel):
    """OTP验证请求"""

    uri: str
    otpPassword: str


class OtpDisableRequest(BaseModel):
    """OTP禁用请求"""

    password: str


class PassKeyDeleteRequest(BaseModel):
    """PassKey删除请求"""

    passkey_id: int
    password: str


class PassKeyRegistrationStart(BaseModel):
    """PassKey注册开始请求"""

    name: str = "通行密钥"


class PassKeyRegistrationFinish(BaseModel):
    """PassKey注册完成请求"""

    credential: dict
    transaction_token: str
    name: str = "通行密钥"


class PassKeyAuthenticationStart(BaseModel):
    """PassKey认证开始请求"""

    username: Optional[str] = None


class PassKeyAuthenticationFinish(BaseModel):
    """PassKey认证完成请求"""

    credential: dict
    transaction_token: str


__all__ = [
    "OtpVerifyRequest",
    "OtpDisableRequest",
    "PassKeyDeleteRequest",
    "PassKeyRegistrationStart",
    "PassKeyRegistrationFinish",
    "PassKeyAuthenticationStart",
    "PassKeyAuthenticationFinish",
]
