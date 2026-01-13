"""2.2.2

Revision ID: 41ef1dd7467c
Revises: a946dae52526
Create Date: 2026-01-13 13:02:41.614029

"""

from app.db import ScopedSession
from app.db.models.systemconfig import SystemConfig
from app.log import logger

# revision identifiers, used by Alembic.
revision = "41ef1dd7467c"
down_revision = "a946dae52526"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # systemconfig表 去重
    with ScopedSession() as db:
        try:
            seen_keys = set()
            # 按ID降序查询，以便保留最新的配置
            for item in db.query(SystemConfig).order_by(SystemConfig.id.desc()).all():
                if item.key in seen_keys:
                    logger.warn(
                        f"已删除重复的SystemConfig项：{item.key} 值:{item.value}"
                    )
                    db.delete(item)
                else:
                    seen_keys.add(item.key)
            db.commit()
        except Exception as e:
            logger.error(e)
            db.rollback()


def downgrade() -> None:
    pass
