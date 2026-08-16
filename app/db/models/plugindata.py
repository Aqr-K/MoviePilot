from typing import Any, Optional
from sqlalchemy import String, JSON, Index, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import (
    db_query,
    db_update,
    async_db_query,
    get_id_column,
    Base,
)
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID


class PluginData(Base):
    """
    插件数据表

    一行数据归属于某个插件实例，由 ``(plugin_id, instance_id, key)`` 定位。
    """
    id = get_id_column()
    plugin_id: Mapped[str] = mapped_column(String, nullable=False)
    # 实例标识，未创建分身时为 DEFAULT_INSTANCE_ID
    instance_id: Mapped[str] = mapped_column(
        String, nullable=False, default=DEFAULT_INSTANCE_ID, server_default=DEFAULT_INSTANCE_ID
    )
    key: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[Optional[Any]] = mapped_column(JSON)

    __table_args__ = (
        Index('ix_plugindata_plugin_instance_key', 'plugin_id', 'instance_id', 'key'),
    )

    @classmethod
    @db_query
    def get_plugin_data(cls, db: Session, plugin_id: str,
                        instance_id: str = DEFAULT_INSTANCE_ID):
        return list(db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        ).scalars().all())

    @classmethod
    @async_db_query
    async def async_get_plugin_data(cls, db: AsyncSession, plugin_id: str,
                                    instance_id: str = DEFAULT_INSTANCE_ID):
        result = await db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        )
        return list(result.scalars().all())

    @classmethod
    @db_query
    def get_plugin_data_by_key(cls, db: Session, plugin_id: str, key: str,
                               instance_id: str = DEFAULT_INSTANCE_ID):
        return db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id,
                              cls.key == key)
        ).scalars().first()

    @classmethod
    @async_db_query
    async def async_get_plugin_data_by_key(
        cls, db: AsyncSession, plugin_id: str, key: str,
        instance_id: str = DEFAULT_INSTANCE_ID
    ):
        result = await db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id,
                              cls.key == key)
        )
        return result.scalar_one_or_none()

    @classmethod
    @db_update
    def del_plugin_data_by_key(cls, db: Session, plugin_id: str, key: str,
                               instance_id: Optional[str] = None):
        """实例ID为空时删除该键在全部实例上的数据。"""
        conditions = [cls.plugin_id == plugin_id, cls.key == key]
        if instance_id is not None:
            conditions.append(cls.instance_id == instance_id)
        db.execute(delete(cls).where(*conditions))

    @classmethod
    @db_update
    def del_plugin_data(cls, db: Session, plugin_id: str, instance_id: Optional[str] = None):
        """实例ID为空时删除该插件全部实例的数据。"""
        conditions = [cls.plugin_id == plugin_id]
        if instance_id is not None:
            conditions.append(cls.instance_id == instance_id)
        db.execute(delete(cls).where(*conditions))

    @classmethod
    @db_query
    def get_plugin_data_by_plugin_id(cls, db: Session, plugin_id: str,
                                     instance_id: str = DEFAULT_INSTANCE_ID):
        return list(db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        ).scalars().all())

    @classmethod
    @async_db_query
    async def async_get_plugin_data_by_plugin_id(
        cls, db: AsyncSession, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID
    ):
        result = await db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        )
        return list(result.scalars().all())
