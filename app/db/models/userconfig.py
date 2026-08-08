from typing import Optional

from sqlalchemy import String, UniqueConstraint, JSON
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import db_query, db_update, get_id_column, Base


class UserConfig(Base):
    """
    用户配置表
    """
    id: Mapped[int] = get_id_column()
    # 用户名
    username: Mapped[Optional[str]] = mapped_column(String)
    # 配置键
    key: Mapped[Optional[str]] = mapped_column(String)
    # 值
    value: Mapped[Optional[dict]] = mapped_column(JSON)

    __table_args__ = (
        # 用户名和配置键联合唯一
        UniqueConstraint('username', 'key'),
    )

    @classmethod
    @db_query
    def get_by_key(cls, db: Session, username: str, key: str):
        return db.query(cls) \
                 .filter(cls.username == username) \
                 .filter(cls.key == key) \
                 .first()

    @db_update
    def delete_by_key(self, db: Session, username: str, key: str):
        userconfig = self.get_by_key(db=db, username=username, key=key)
        if userconfig:
            userconfig.delete(db=db, rid=userconfig.id)
        return True
