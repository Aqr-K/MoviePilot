# -*- coding: utf-8 -*-
from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.common import JsonData
from app.schemas.token import Token


class AuthExchangeRequest(BaseModel):
    """
    插件认证票据兑换请求。
    """

    ticket: str


class FlowBeginRequest(BaseModel):
    """开始多步登录流程的请求（通常携带用户名/口令；也可用于纯枚举步骤）。"""

    username: Optional[str] = None
    password: Optional[str] = None
    grant_type: str = "password"
    # 步骤选择器：携带某个 SSO/重定向步的 step_id（如 "github"）时，begin 直接定向到该步下发跳转挑战，
    # 使 SSO 与密码/因子走同一条统一流程（spec §5/§6）。缺省（None）为纯密码/枚举 begin，不受影响。
    flow: Optional[str] = None


class FlowAdvanceRequest(BaseModel):
    """推进多步登录流程的请求（提交因子码 / 挑战应答 / 后补凭证）。"""

    flow_token: str
    step_id: Optional[str] = None
    code: Optional[str] = None
    response: Optional[dict[str, JsonData]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    grant_type: str = "password"


class FlowStateData(BaseModel):
    """多步登录流程的状态应答（begin / advance 共用）。"""

    # success / mfa_required / challenge / continue
    status: str
    # status 为 success 时携带的访问令牌
    token: Optional[Token] = None
    # 后续调用 /auth/flow/advance 推进所用的流程令牌
    flow_token: Optional[str] = None
    # 当前可用的第二因子标识
    factors_available: list[str] = Field(default_factory=list)
    # 待应答的挑战内容（如 SSO 的 authorize_url、WebAuthn 选项）
    challenge: Optional[dict[str, JsonData]] = None
    # 失败原因（已按白名单脱敏）
    error: Optional[str] = None


__all__ = [
    "AuthExchangeRequest",
    "FlowBeginRequest",
    "FlowAdvanceRequest",
    "FlowStateData",
]
