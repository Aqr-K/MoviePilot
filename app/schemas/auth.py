# -*- coding: utf-8 -*-
from typing import Optional

from pydantic import BaseModel


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
    response: Optional[dict] = None
    username: Optional[str] = None
    password: Optional[str] = None
    grant_type: str = "password"


__all__ = ["AuthExchangeRequest", "FlowBeginRequest", "FlowAdvanceRequest"]
