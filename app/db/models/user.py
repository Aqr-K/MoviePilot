from typing import Tuple, Any

from sqlalchemy import Boolean, Column, Integer, String, Sequence, JSON, inspect
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db import db_query, db_update, Base
from app.utils.otp import OtpUtils


class User(Base):
    """
    用户表
    """
    # ID
    id = Column(Integer, Sequence('id'), primary_key=True, index=True)
    # 用户名，唯一值
    name = Column(String, index=True, nullable=False)
    # 邮箱
    email = Column(String)
    # 加密后密码
    hashed_password = Column(String)
    # 是否启用
    is_active = Column(Boolean(), default=True)
    # 是否管理员
    is_superuser = Column(Boolean(), default=False)
    # 头像
    avatar = Column(String)
    # 是否启用otp二次验证
    is_otp = Column(Boolean(), default=False)
    # otp秘钥
    otp_secret = Column(String, default=None)
    # 用户权限 json
    permissions = Column(JSON, default=dict)
    # 用户个性化设置 json
    settings = Column(JSON, default=dict)

    @staticmethod
    @db_query
    def authenticate(db: Session, name: str, password: str,
                     otp_password: str) -> Tuple[bool, Any]:
        user = db.query(User).filter(User.name == name).first()
        if not user:
            return False, None
        if not verify_password(password, str(user.hashed_password)):
            return False, user
        if user.is_otp:
            if not otp_password or not OtpUtils.check(str(user.otp_secret), otp_password):
                return False, user
        return True, user

    @staticmethod
    @db_query
    def get_by_name(db: Session, name: str):
        return db.query(User).filter(User.name == name).first()

    @staticmethod
    @db_query
    def get_by_id(db: Session, user_id: int):
        return db.query(User).filter(User.id == user_id).first()

    @db_update
    def delete_by_name(self, db: Session, name: str):
        user = self.get_by_name(db, name)
        if user:
            user.delete(db, user.id)
        return True

    @db_update
    def delete_by_id(self, db: Session, user_id: int):
        user = self.get_by_id(db, user_id)
        if user:
            user.delete(db, user.id)
        return True

    @db_update
    def update_otp_by_name(self, db: Session, name: str, otp: bool, secret: str):
        user = self.get_by_name(db, name)
        if user:
            user.update(db, {
                'is_otp': otp,
                'otp_secret': secret
            })
            return True
        return False
