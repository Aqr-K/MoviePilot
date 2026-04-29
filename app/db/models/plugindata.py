from sqlalchemy import Column, String, JSON, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db import (
    db_query,
    db_update,
    async_db_query,
    get_id_column,
    Base,
)


class PluginData(Base):
    """
    插件数据表
    """
    id = get_id_column()
    plugin_id = Column(String, nullable=False, index=True)
    key = Column(String, index=True, nullable=False)
    value = Column(JSON)

    @classmethod
    @db_query
    def get_plugin_data(cls, db: Session, plugin_id: str):
        return db.query(cls).filter(cls.plugin_id == plugin_id).all()

    @classmethod
    @async_db_query
    async def async_get_plugin_data(cls, db: AsyncSession, plugin_id: str):
        result = await db.execute(select(cls).where(cls.plugin_id == plugin_id))
        return result.scalars().all()

    @classmethod
    @db_query
    def get_plugin_data_by_key(cls, db: Session, plugin_id: str, key: str):
        return db.query(cls).filter(cls.plugin_id == plugin_id, cls.key == key).first()

    @classmethod
    @async_db_query
    async def async_get_plugin_data_by_key(
        cls, db: AsyncSession, plugin_id: str, key: str
    ):
        result = await db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.key == key)
        )
        return result.scalar_one_or_none()

    @classmethod
    @db_update
    def del_plugin_data_by_key(cls, db: Session, plugin_id: str, key: str):
        db.query(cls).filter(cls.plugin_id == plugin_id, cls.key == key).delete()

    @classmethod
    @db_update
    def del_plugin_data(cls, db: Session, plugin_id: str):
        db.query(cls).filter(cls.plugin_id == plugin_id).delete()

    @classmethod
    @db_query
    def get_plugin_data_by_plugin_id(cls, db: Session, plugin_id: str):
        return db.query(cls).filter(cls.plugin_id == plugin_id).all()

    @classmethod
    @async_db_query
    async def async_get_plugin_data_by_plugin_id(
        cls, db: AsyncSession, plugin_id: str
    ):
        result = await db.execute(select(cls).where(cls.plugin_id == plugin_id))
        return result.scalars().all()
