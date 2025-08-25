"""2.2.1

Revision ID: a946dae52526
Revises: 5b3355c964bb
Create Date: 2025-08-20 17:50:00.000000

"""
import sqlalchemy as sa
from alembic import op

from app.log import logger
from app.core.config import settings

# revision identifiers, used by Alembic.
revision = 'a946dae52526'
down_revision = '5b3355c964bb'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    升级：将SiteUserData表的userid字段从Integer改为String
    """
    connection = op.get_bind()
    
    if settings.DB_TYPE.lower() == "postgresql":
        # PostgreSQL数据库迁移
        migrate_postgresql_userid(connection)
    else:
        # SQLite数据库迁移
        migrate_sqlite_userid(connection)


def downgrade() -> None:
    """
    降级：将SiteUserData表的userid字段从String改回Integer
    """
    pass


def migrate_postgresql_userid(connection):
    """
    PostgreSQL数据库userid字段迁移
    """
    try:
        logger.info("开始PostgreSQL数据库userid字段迁移...")
        
        # 1. 创建临时列
        connection.execute(sa.text("""
            ALTER TABLE siteuserdata 
            ADD COLUMN userid_new VARCHAR
        """))
        
        # 2. 将现有数据转换为字符串并复制到新列
        connection.execute(sa.text("""
            UPDATE siteuserdata 
            SET userid_new = CAST(userid AS VARCHAR)
            WHERE userid IS NOT NULL
        """))
        
        # 3. 删除旧列
        connection.execute(sa.text("""
            ALTER TABLE siteuserdata 
            DROP COLUMN userid
        """))
        
        # 4. 重命名新列
        connection.execute(sa.text("""
            ALTER TABLE siteuserdata 
            RENAME COLUMN userid_new TO userid
        """))
        
        logger.info("PostgreSQL数据库userid字段迁移完成")
        
    except Exception as e:
        logger.error(f"PostgreSQL数据库userid字段迁移失败: {e}")
        raise


def migrate_sqlite_userid(connection):
    """
    SQLite数据库userid字段迁移
    """
    try:
        logger.info("开始SQLite数据库userid字段迁移...")
        
        # SQLite不支持直接修改列类型，需要重建表
        # 1. 创建新表结构
        connection.execute(sa.text("""
            CREATE TABLE siteuserdata_new (
                id INTEGER PRIMARY KEY,
                domain VARCHAR,
                name VARCHAR,
                username VARCHAR,
                userid VARCHAR,
                user_level VARCHAR,
                join_at VARCHAR,
                bonus FLOAT DEFAULT 0,
                upload FLOAT DEFAULT 0,
                download FLOAT DEFAULT 0,
                ratio FLOAT DEFAULT 0,
                seeding FLOAT DEFAULT 0,
                leeching FLOAT DEFAULT 0,
                seeding_size FLOAT DEFAULT 0,
                leeching_size FLOAT DEFAULT 0,
                seeding_info JSON DEFAULT '{}',
                message_unread INTEGER DEFAULT 0,
                message_unread_contents JSON DEFAULT '[]',
                err_msg VARCHAR,
                updated_day VARCHAR,
                updated_time VARCHAR
            )
        """))
        
        # 2. 复制数据，将userid转换为字符串
        connection.execute(sa.text("""
            INSERT INTO siteuserdata_new 
            SELECT 
                id, domain, name, username, 
                CAST(userid AS VARCHAR) as userid,
                user_level, join_at, bonus, upload, download, ratio,
                seeding, leeching, seeding_size, leeching_size,
                seeding_info, message_unread, message_unread_contents,
                err_msg, updated_day, updated_time
            FROM siteuserdata
        """))
        
        # 3. 删除旧表
        connection.execute(sa.text("DROP TABLE siteuserdata"))
        
        # 4. 重命名新表
        connection.execute(sa.text("ALTER TABLE siteuserdata_new RENAME TO siteuserdata"))
        
        # 5. 重新创建索引
        connection.execute(sa.text("CREATE INDEX ix_siteuserdata_domain ON siteuserdata (domain)"))
        connection.execute(sa.text("CREATE INDEX ix_siteuserdata_updated_day ON siteuserdata (updated_day)"))
        
        logger.info("SQLite数据库userid字段迁移完成")
        
    except Exception as e:
        logger.error(f"SQLite数据库userid字段迁移失败: {e}")
        raise


