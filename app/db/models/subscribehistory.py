from typing import Optional

from sqlalchemy import Integer, String, Float, JSON, Index, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import db_query, Base, get_id_column, async_db_query


class SubscribeHistory(Base):
    """
    订阅历史表
    """
    id: Mapped[int] = get_id_column()
    # 标题
    name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # 年份
    year: Mapped[Optional[str]] = mapped_column(String)
    # 类型
    type: Mapped[Optional[str]] = mapped_column(String)
    # 搜索关键字
    keyword: Mapped[Optional[str]] = mapped_column(String)
    tmdbid: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    imdbid: Mapped[Optional[str]] = mapped_column(String)
    tvdbid: Mapped[Optional[int]] = mapped_column(Integer)
    doubanid: Mapped[Optional[str]] = mapped_column(String, index=True)
    bangumiid: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    mediaid: Mapped[Optional[str]] = mapped_column(String, index=True)
    # 季号
    season: Mapped[Optional[int]] = mapped_column(Integer)
    # 海报
    poster: Mapped[Optional[str]] = mapped_column(String)
    # 背景图
    backdrop: Mapped[Optional[str]] = mapped_column(String)
    # 评分，float
    vote: Mapped[Optional[float]] = mapped_column(Float)
    # 简介
    description: Mapped[Optional[str]] = mapped_column(String)
    # 过滤规则
    filter: Mapped[Optional[str]] = mapped_column(String)
    # 包含
    include: Mapped[Optional[str]] = mapped_column(String)
    # 排除
    exclude: Mapped[Optional[str]] = mapped_column(String)
    # 质量
    quality: Mapped[Optional[str]] = mapped_column(String)
    # 分辨率
    resolution: Mapped[Optional[str]] = mapped_column(String)
    # 特效
    effect: Mapped[Optional[str]] = mapped_column(String)
    # 总集数
    total_episode: Mapped[Optional[int]] = mapped_column(Integer)
    # 开始集数
    start_episode: Mapped[Optional[int]] = mapped_column(Integer)
    # 订阅完成时间
    date: Mapped[Optional[str]] = mapped_column(String)
    # 订阅用户
    username: Mapped[Optional[str]] = mapped_column(String)
    # 订阅站点
    sites: Mapped[Optional[dict]] = mapped_column(JSON)
    # 是否洗版
    best_version: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    # 是否只洗全集整包，开启后电视剧洗版不按单集下载
    best_version_full: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    # 洗版时已下载剧集的优先级状态，格式：{"1": 90, "2": 100}
    episode_priority: Mapped[Optional[dict]] = mapped_column(JSON)
    # 保存路径
    save_path: Mapped[Optional[str]] = mapped_column(String)
    # 是否使用 imdbid 搜索
    search_imdbid: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    # 自定义识别词
    custom_words: Mapped[Optional[str]] = mapped_column(String)
    # 自定义媒体类别
    media_category: Mapped[Optional[str]] = mapped_column(String)
    # 过滤规则组
    filter_groups: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    # 剧集组
    episode_group: Mapped[Optional[str]] = mapped_column(String)

    __table_args__ = (
        Index('ix_subscribehistory_type_date', 'type', 'date'),
    )

    @classmethod
    @db_query
    def list_by_type(cls, db: Session, mtype: str, page: Optional[int] = 1, count: Optional[int] = 30):
        return db.query(cls).filter(
            cls.type == mtype
        ).order_by(
            cls.date.desc()
        ).offset((page - 1) * count).limit(count).all()

    @classmethod
    @async_db_query
    async def async_list_by_type(cls, db: AsyncSession, mtype: str, page: Optional[int] = 1, count: Optional[int] = 30):
        result = await db.execute(
            select(cls).filter(
                cls.type == mtype
            ).order_by(
                cls.date.desc()
            ).offset((page - 1) * count).limit(count)
        )
        return result.scalars().all()

    @classmethod
    @async_db_query
    async def async_list_by_type_and_username(
            cls,
            db: AsyncSession,
            mtype: str,
            username: str,
            page: Optional[int] = 1,
            count: Optional[int] = 30
    ):
        """
        按订阅 owner 查询指定类型的历史分页。
        """
        if not username:
            return []
        result = await db.execute(
            select(cls).filter(
                cls.type == mtype,
                cls.username == username
            ).order_by(
                cls.date.desc()
            ).offset((page - 1) * count).limit(count)
        )
        return result.scalars().all()

    @classmethod
    @db_query
    def exists(cls, db: Session, tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
               season: Optional[int] = None):
        if tmdbid:
            if season is not None:
                return db.query(cls).filter(cls.tmdbid == tmdbid,
                                            cls.season == season).first()
            return db.query(cls).filter(cls.tmdbid == tmdbid).first()
        elif doubanid:
            return db.query(cls).filter(cls.doubanid == doubanid).first()
        return None

    @classmethod
    @async_db_query
    async def async_exists(cls, db: AsyncSession, tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
                           season: Optional[int] = None):
        if tmdbid:
            if season is not None:
                result = await db.execute(
                    select(cls).filter(cls.tmdbid == tmdbid, cls.season == season)
                )
            else:
                result = await db.execute(
                    select(cls).filter(cls.tmdbid == tmdbid)
                )
        elif doubanid:
            result = await db.execute(
                select(cls).filter(cls.doubanid == doubanid)
            )
        else:
            return None
        return result.scalars().first()
