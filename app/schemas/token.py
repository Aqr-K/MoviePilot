from typing import List, Optional

from pydantic import BaseModel, Field


class Token(BaseModel):
    # 令牌
    access_token: str
    # 令牌类型
    token_type: str
    # 超级用户
    super_user: bool
    # 用户ID
    user_id: int
    # 用户名
    user_name: str
    # 头像
    avatar: Optional[str] = None
    # 权限级别
    level: int = 1
    # 详细权限
    permissions: Optional[dict] = Field(default_factory=dict)
    # 是否显示配置向导
    wizard: Optional[bool] = None
    # 登录结果状态："success" | "mfa_required" | "challenge"（PR6 结构化响应，附加字段，旧端忽略）
    status: Optional[str] = None
    # 需 MFA 时可用的第二因子 id 列表（前端据此渲染因子选择）
    factors_available: Optional[List[str]] = None


class TokenPayload(BaseModel):
    # 用户ID
    sub: Optional[int] = None
    # 用户名
    username: Optional[str] = None
    # 超级用户
    super_user: Optional[bool] = None
    # 权限级别
    level: Optional[int] = None
    # 令牌用途 authentication\resource
    purpose: Optional[str] = None
