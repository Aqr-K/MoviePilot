from datetime import datetime
from typing import Optional, List

from sqlalchemy import Integer, String, JSON, Index, or_
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import db_query, db_update, get_id_column, async_db_query, Base
from app.db.models.media_identity import media_identity_constraint
from app.schemas.types import MediaSource


class MediaServerItem(Base):
    """
    媒体服务器媒体条目表
    """
    id: Mapped[int] = get_id_column()
    # 服务器类型
    server: Mapped[Optional[str]] = mapped_column(String)
    # 媒体库ID
    library: Mapped[Optional[str]] = mapped_column(String)
    # ID
    item_id: Mapped[Optional[str]] = mapped_column(String, index=True)
    # 类型
    item_type: Mapped[Optional[str]] = mapped_column(String)
    # 标题
    title: Mapped[Optional[str]] = mapped_column(String, index=True)
    # 原标题
    original_title: Mapped[Optional[str]] = mapped_column(String)
    # 年份
    year: Mapped[Optional[str]] = mapped_column(String)
    # 媒体数据源与原生ID
    media_source: Mapped[Optional[str]] = mapped_column(String, index=True)
    media_id: Mapped[Optional[str]] = mapped_column(String, index=True)
    # 路径
    path: Mapped[Optional[str]] = mapped_column(String)
    # 季集
    seasoninfo: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    # 备注
    note: Mapped[Optional[dict]] = mapped_column(JSON)
    # 同步时间
    lst_mod_date: Mapped[Optional[str]] = mapped_column(String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    __table_args__ = (
        media_identity_constraint("mediaserveritem"),
        Index('ux_mediaserveritem_server_item_id', 'server', 'item_id', unique=True),
        Index(
            'ix_mediaserveritem_media_identity_type',
            'media_source', 'media_id', 'item_type',
        ),
    )

    @classmethod
    @db_query
    def get_by_itemid(cls, db: Session, item_id: str):
        return db.query(cls).filter(cls.item_id == item_id).first()

    @classmethod
    @db_query
    def get_by_server_itemid(cls, db: Session, server: str, item_id: str):
        return db.query(cls).filter(cls.server == server,
                                    cls.item_id == item_id).first()

    @classmethod
    @db_update
    def empty(cls, db: Session, server: Optional[str] = None):
        if server is None:
            db.query(cls).delete(synchronize_session=False)
        else:
            db.query(cls).filter(cls.server == server).delete(synchronize_session=False)

    @classmethod
    @db_update
    def delete_stale(cls, db: Session, server: str, sync_time: str):
        return db.query(cls).filter(cls.server == server,
                                    or_(cls.lst_mod_date.is_(None),
                                        cls.lst_mod_date != sync_time)).delete(synchronize_session=False)

    @classmethod
    @db_update
    def delete_excluded_servers(cls, db: Session, servers: List[str]):
        if not servers:
            return db.query(cls).delete(synchronize_session=False)
        return db.query(cls).filter(or_(cls.server.is_(None),
                                        ~cls.server.in_(servers))).delete(synchronize_session=False)

    @classmethod
    @db_query
    def exist_by_media_identity(
            cls, db: Session, media_source: MediaSource, media_id: str, mtype: str,
    ):
        """按规范媒体身份和类型查询媒体服务器条目。"""
        return db.query(cls).filter(
            cls.media_source == str(media_source),
            cls.media_id == str(media_id),
            cls.item_type == mtype,
        ).first()

    @classmethod
    @db_query
    def exists_by_title(cls, db: Session, title: str, mtype: str, year: str):
        if not mtype and not year:
            return db.query(cls).filter(cls.title == title).first()
        elif not year:
            return db.query(cls).filter(cls.title == title,
                                        cls.item_type == mtype).first()
        elif not mtype:
            return db.query(cls).filter(cls.title == title,
                                        cls.year == str(year)).first()
        return db.query(cls).filter(cls.title == title,
                                    cls.item_type == mtype,
                                    cls.year == str(year)).first()

    @classmethod
    @async_db_query
    async def async_get_by_itemid(cls, db: AsyncSession, item_id: str):
        result = await db.execute(select(cls).filter(cls.item_id == item_id))
        return result.scalars().first()

    @classmethod
    @async_db_query
    async def async_exist_by_media_identity(
            cls, db: AsyncSession, media_source: MediaSource, media_id: str, mtype: str,
    ):
        """异步按规范媒体身份和类型查询媒体服务器条目。"""
        result = await db.execute(select(cls).filter(
            cls.media_source == str(media_source),
            cls.media_id == str(media_id),
            cls.item_type == mtype,
        ))
        return result.scalars().first()

    @classmethod
    @async_db_query
    async def async_exists_by_title(cls, db: AsyncSession, title: str, mtype: str, year: str):
        if not mtype and not year:
            result = await db.execute(select(cls).filter(cls.title == title))
        elif not year:
            result = await db.execute(select(cls).filter(cls.title == title,
                                                         cls.item_type == mtype))
        elif not mtype:
            result = await db.execute(select(cls).filter(cls.title == title,
                                                         cls.year == str(year)))
        else:
            result = await db.execute(select(cls).filter(cls.title == title,
                                                     cls.item_type == mtype,
                                                     cls.year == str(year)))
        return result.scalars().first()
