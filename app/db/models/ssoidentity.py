from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db import Base, async_db_query, db_query, get_id_column


class SsoIdentity(Base):
    """
    SSO 外部身份 ↔ 本地用户 绑定表。

    按稳定的 (provider_id, subject) 唯一映射到本地 user，使得：
      - 外部用户改名（username 变）不丢号——解析以 subject 为主键，与可变用户名解耦；
      - 支持账号关联（把一个外部身份绑定到已存在的本地用户）与多提供方并存。
    身份持久化属用户账号域（框架表），不随插件卸载而失，故不放插件 plugin_data。
    """
    # ID
    id = get_id_column()
    # 提供方标识（如 github），与 app.core.sso 注册的 provider_id 一致
    provider_id = Column(String, nullable=False, index=True)
    # IdP 侧稳定用户标识（OIDC sub / GitHub 数字 id 等），绑定主键之一
    subject = Column(String, nullable=False)
    # 本地用户 ID（用户删除时级联清理绑定，避免孤儿行；sqlite 需开启 FK 约束才生效）
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    # 外部用户名快照（仅用于展示/审计，不参与身份解析）
    username = Column(String, nullable=True)
    # 创建时间
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        UniqueConstraint('provider_id', 'subject', name='uq_ssoidentity_provider_subject'),
    )

    @classmethod
    @db_query
    def get_by_subject(cls, db: Session, provider_id: str, subject: str):
        """按 (provider_id, subject) 取绑定，不存在返回 None。"""
        return db.query(cls).filter(cls.provider_id == provider_id, cls.subject == subject).first()

    @classmethod
    @db_query
    def list_by_user(cls, db: Session, user_id: int):
        """列出某本地用户的所有外部身份绑定（供账号关联管理）。"""
        return db.query(cls).filter(cls.user_id == user_id).all()

    @classmethod
    @async_db_query
    async def async_get_by_subject(cls, db: AsyncSession, provider_id: str, subject: str):
        """异步按 (provider_id, subject) 取绑定。"""
        result = await db.execute(
            select(cls).filter(cls.provider_id == provider_id, cls.subject == subject)
        )
        return result.scalars().first()
