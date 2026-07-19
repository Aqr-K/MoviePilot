from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base, db_query, db_update, get_id_column


class AgentTask(Base):
    """
    Agent 自主定时任务表。
    """

    id: Mapped[int] = get_id_column()
    # 任务名称
    name: Mapped[str] = mapped_column(String, nullable=False)
    # 交给 Agent 执行的完整任务内容
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # 触发类型：date-单次触发，cron-周期触发
    trigger_type: Mapped[str] = mapped_column(String, nullable=False)
    # 标准五段 cron 表达式
    cron_expression: Mapped[Optional[str]] = mapped_column(String)
    # 单次触发时间，使用带时区的 ISO 8601 格式
    run_at: Mapped[Optional[str]] = mapped_column(String)
    # 是否继续接受调度
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # 创建任务的用户与会话上下文
    user_id: Mapped[str] = mapped_column(String, nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String)
    session_id: Mapped[str] = mapped_column(String, nullable=False)
    channel: Mapped[Optional[str]] = mapped_column(String)
    source: Mapped[Optional[str]] = mapped_column(String)
    original_chat_id: Mapped[Optional[str]] = mapped_column(String)
    # 最近一次执行状态与结果
    last_status: Mapped[str] = mapped_column(String, nullable=False, default="waiting")
    last_run_at: Mapped[Optional[str]] = mapped_column(String)
    last_result: Mapped[Optional[str]] = mapped_column(Text)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("ix_agenttask_enabled", "enabled"),
        Index("ix_agenttask_user_created", "user_id", "created_at", "id"),
    )

    @classmethod
    @db_update
    def add_task(cls, db: Session, **kwargs: object) -> int:
        """
        新增 Agent 定时任务并返回任务 ID。
        """
        task = cls(**kwargs)
        db.add(task)
        db.flush()
        return task.id

    @classmethod
    @db_query
    def get_for_user(
            cls,
            db: Session,
            task_id: int,
            user_id: Optional[str] = None,
    ) -> Optional["AgentTask"]:
        """
        按任务 ID 和可选用户 ID 查询 Agent 定时任务。
        """
        query = db.query(cls).filter(cls.id == task_id)
        if user_id is not None:
            query = query.filter(cls.user_id == user_id)
        return query.first()

    @classmethod
    @db_query
    def list_for_user(
            cls,
            db: Session,
            user_id: Optional[str] = None,
            enabled: Optional[bool] = None,
    ) -> list["AgentTask"]:
        """
        按用户和启用状态查询 Agent 定时任务。
        """
        query = db.query(cls)
        if user_id is not None:
            query = query.filter(cls.user_id == user_id)
        if enabled is not None:
            query = query.filter(cls.enabled.is_(enabled))
        return query.order_by(cls.created_at.desc(), cls.id.desc()).all()

    @classmethod
    @db_update
    def update_task(
            cls,
            db: Session,
            task_id: int,
            payload: dict,
            user_id: Optional[str] = None,
    ) -> bool:
        """
        按任务 ID 和可选用户 ID 更新 Agent 定时任务。
        """
        query = db.query(cls).filter(cls.id == task_id)
        if user_id is not None:
            query = query.filter(cls.user_id == user_id)
        return bool(query.update(payload))

    @classmethod
    @db_update
    def delete_task(
            cls,
            db: Session,
            task_id: int,
            user_id: Optional[str] = None,
    ) -> bool:
        """
        按任务 ID 和可选用户 ID 删除 Agent 定时任务。
        """
        query = db.query(cls).filter(cls.id == task_id)
        if user_id is not None:
            query = query.filter(cls.user_id == user_id)
        return bool(query.delete())

    @classmethod
    @db_update
    def mark_running(cls, db: Session, task_id: int, run_at: str) -> bool:
        """
        将可执行任务标记为运行中。
        """
        updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return bool(
            db.query(cls)
            .filter(
                cls.id == task_id,
                cls.enabled.is_(True),
                cls.last_status != "running",
            )
            .update(
                {
                    "last_status": "running",
                    "last_run_at": run_at,
                    "updated_at": updated_at,
                }
            )
        )

    @classmethod
    @db_update
    def finish_task(
            cls,
            db: Session,
            task_id: int,
            success: bool,
            result: str,
            disable: bool = False,
    ) -> bool:
        """
        记录 Agent 定时任务执行结果，并按需关闭单次任务。
        """
        payload = {
            "last_status": "success" if success else "failed",
            "last_result": result,
            "run_count": cls.run_count + 1,
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if disable:
            payload["enabled"] = False
        return bool(db.query(cls).filter(cls.id == task_id).update(payload))
