from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base, async_db_query, db_query, get_id_column


class ExternalIdentity(Base):
    """外部身份 ↔ 本地用户 绑定表。

    记录「某个外部认证来源识别出的主体」与「本地用户」之间的稳定映射，
    供所有联邦化登录车道复用，而不局限于 SSO 重定向：

    - ``IAuthProvider`` 车道（OAuth2/OIDC 授权码重定向，见 ``app/core/auth/redirect.py``）；
    - ``ICredentialProvider`` 车道中的「外部直验」凭据源（如对接外部目录/账号系统，
      经 ``app/service/auth/provisioning.resolve_or_create`` 落绑定）。

    绑定以 ``(provider_id, subject)`` 为业务主键：``provider_id`` 标识外部来源
    （SSO Provider 或外部凭据 Provider 的注册 id），``subject`` 是该来源对主体的
    稳定标识（OIDC ``sub``、目录 DN、外部用户 id 等）。登录解析始终以该二元组
    命中绑定，``username`` 仅作展示/派生留痕，不参与匹配。
    """

    id: Mapped[int] = get_id_column()
    # 外部来源 id（SSO Provider 或外部凭据 Provider 的注册标识）
    provider_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # 外部来源对主体的稳定标识（OIDC sub、目录 DN、外部用户 id 等）
    subject: Mapped[str] = mapped_column(String, nullable=False)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True
    )
    # 绑定建立时的外部用户名留痕（仅展示/派生用，不参与解析匹配）
    username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.now)

    __table_args__ = (
        UniqueConstraint('provider_id', 'subject', name='uq_externalidentity_provider_subject'),
    )

    @classmethod
    @db_query
    def get_by_subject(cls, db: Session, provider_id: str, subject: str):
        """按 ``(provider_id, subject)`` 命中绑定（外部主体 → 本地用户）。"""
        return db.query(cls).filter(cls.provider_id == provider_id, cls.subject == subject).first()

    @classmethod
    @db_query
    def list_by_user(cls, db: Session, user_id: int):
        """列出某本地用户已绑定的全部外部身份。"""
        return db.query(cls).filter(cls.user_id == user_id).all()

    @classmethod
    @async_db_query
    async def async_get_by_subject(cls, db: AsyncSession, provider_id: str, subject: str):
        """``get_by_subject`` 的异步版本。"""
        result = await db.execute(
            select(cls).filter(cls.provider_id == provider_id, cls.subject == subject)
        )
        return result.scalars().first()
