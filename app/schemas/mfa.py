"""多因素认证 API 输入输出模型。"""

from typing import Optional

from pydantic import BaseModel, Field, RootModel

from app.schemas.common import JsonData


class PasskeyOptions(RootModel[dict[str, JsonData]]):
    """浏览器 WebAuthn API 使用的动态选项。"""


class OtpGenerateData(BaseModel):
    """OTP 绑定密钥和验证 URI。"""

    secret: str = Field(description="OTP 密钥")
    uri: str = Field(description="OTP 验证 URI")


class MfaStatusData(BaseModel):
    """用户是否启用多因素认证。"""

    enabled: bool = Field(description="是否启用多因素认证")


class PasskeyStartData(BaseModel):
    """PassKey 注册或认证的启动数据。"""

    options: PasskeyOptions = Field(description="WebAuthn 选项")
    transaction_token: str = Field(description="一次性事务令牌")


class PasskeyInfo(BaseModel):
    """当前用户绑定的 PassKey 摘要。"""

    id: int
    name: str
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    aaguid: Optional[str] = None
    transports: Optional[str] = None


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
    "PasskeyOptions",
    "OtpGenerateData",
    "MfaStatusData",
    "PasskeyStartData",
    "PasskeyInfo",
    "OtpVerifyRequest",
    "OtpDisableRequest",
    "PassKeyDeleteRequest",
    "PassKeyRegistrationStart",
    "PassKeyRegistrationFinish",
    "PassKeyAuthenticationStart",
    "PassKeyAuthenticationFinish",
]
