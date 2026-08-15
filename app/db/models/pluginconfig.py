from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import Boolean, DateTime, JSON, String, UniqueConstraint, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import (
    Base,
    async_db_query,
    db_query,
    get_id_column,
)

# 插件独立日志等级的合法取值
LOG_LEVELS = ("DEBUG", "INFO", "WARN", "ERROR")

# 插件未创建分身时使用的主实例标识
DEFAULT_INSTANCE_ID = "default"


class PluginConfig(Base):
    """
    插件实例配置表

    一个插件类可以拥有多个实例（分身），每个实例由 ``(plugin_id, instance_id)`` 唯一确定，
    并持有各自独立的启用状态、日志等级与业务参数。
    """
    id = get_id_column()
    # 实例标识，在同一插件内唯一；未创建分身时为 DEFAULT_INSTANCE_ID
    instance_id: Mapped[str] = mapped_column(String, nullable=False)
    # 插件标识，对应插件类名
    plugin_id: Mapped[str] = mapped_column(String, nullable=False)
    # 该实例是否启用
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 该实例独立的日志等级，为空时跟随全局等级
    log_level: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # 日志等级的失效时间，用于临时调试后自动恢复，为空表示不过期
    log_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # 插件业务参数
    config_data: Mapped[Optional[Any]] = mapped_column(JSON)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)

    __table_args__ = (
        UniqueConstraint("instance_id", "plugin_id", name="uk_instance_plugin"),
    )

    @classmethod
    @db_query
    def get_instance(cls, db: Session, plugin_id: str, instance_id: str):
        """
        查询单个插件实例的配置

        :param plugin_id: 插件标识
        :param instance_id: 实例标识
        :return: 命中的配置记录，无则 None
        """
        return db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        ).scalars().first()

    @classmethod
    @async_db_query
    async def async_get_instance(cls, db: AsyncSession, plugin_id: str, instance_id: str):
        """
        异步查询单个插件实例的配置

        :param plugin_id: 插件标识
        :param instance_id: 实例标识
        :return: 命中的配置记录，无则 None
        """
        result = await db.execute(
            select(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        )
        return result.scalars().first()

    @classmethod
    @db_query
    def list_by_plugin(cls, db: Session, plugin_id: str) -> List["PluginConfig"]:
        """
        列出某个插件的全部实例配置

        :param plugin_id: 插件标识
        :return: 按实例标识升序排列的配置记录
        """
        return list(db.execute(
            select(cls).where(cls.plugin_id == plugin_id).order_by(cls.instance_id)
        ).scalars().all())

    @classmethod
    @db_query
    def list_all(cls, db: Session) -> List["PluginConfig"]:
        """
        列出全部插件实例配置

        :return: 按插件标识、实例标识升序排列的配置记录
        """
        return list(db.execute(
            select(cls).order_by(cls.plugin_id, cls.instance_id)
        ).scalars().all())

    @classmethod
    @db_query
    def list_enabled(cls, db: Session) -> List["PluginConfig"]:
        """
        列出全部已启用的插件实例配置

        :return: 按插件标识、实例标识升序排列的配置记录
        """
        return list(db.execute(
            select(cls).where(cls.is_enabled.is_(True)).order_by(cls.plugin_id, cls.instance_id)
        ).scalars().all())

    @classmethod
    @db_query
    def delete_instance(cls, db: Session, plugin_id: str, instance_id: str):
        """
        删除单个插件实例的配置

        :param plugin_id: 插件标识
        :param instance_id: 实例标识
        """
        db.execute(
            delete(cls).where(cls.plugin_id == plugin_id, cls.instance_id == instance_id)
        )

    @classmethod
    @db_query
    def delete_plugin(cls, db: Session, plugin_id: str):
        """
        删除某个插件的全部实例配置

        :param plugin_id: 插件标识
        """
        db.execute(delete(cls).where(cls.plugin_id == plugin_id))
