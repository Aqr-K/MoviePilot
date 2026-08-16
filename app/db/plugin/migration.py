"""
插件自管理迁移。

插件把 versions/ 与本模块生成的通用 env.py 放在自己的迁移目录下，运行器把
「插件容器的连接 + MetaData + 版本表 schema」注入 Alembic Config.attributes，
由 env 读取后执行 upgrade。版本隔离天然成立：SQLite 每插件独立库文件、
PostgreSQL 每插件独立 schema，alembic_version 因而各自独立。
"""
from pathlib import Path
from typing import Union

from alembic import command
from alembic.config import Config

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.db.plugin.registry import _pg_create_schema_ddl, db_manager

# 通用 env.py 模板，连接、元数据与版本表 schema 均由运行器经 config.attributes 注入
PLUGIN_ALEMBIC_ENV = '''"""插件自管理迁移的通用 Alembic env（由 app.db.plugin.migration 运行器注入连接）。"""
from alembic import context

config = context.config
connection = config.attributes.get("connection")
target_metadata = config.attributes.get("target_metadata")
version_table_schema = config.attributes.get("version_table_schema")

if connection is None:
    raise RuntimeError("插件迁移需由 run_plugin_migrations 注入已绑定的连接")

context.configure(
    connection=connection,
    target_metadata=target_metadata,
    version_table_schema=version_table_schema,
)
with context.begin_transaction():
    context.run_migrations()
'''


def write_plugin_alembic_env(script_location: Union[str, Path]) -> Path:
    """
    将通用 env.py 模板写入插件迁移目录，幂等覆盖

    插件只需维护 ``script_location/versions/*.py``，env.py 交由本函数生成。
    :param script_location: 插件迁移目录
    :return: 写入的 env.py 路径
    """
    location = Path(script_location)
    location.mkdir(parents=True, exist_ok=True)
    env_path = location / "env.py"
    env_path.write_text(PLUGIN_ALEMBIC_ENV, encoding="utf-8")
    return env_path


def run_plugin_migrations(
        plugin_id: str,
        script_location: Union[str, Path],
        revision: str = "head",
        instance_id: str = DEFAULT_INSTANCE_ID,
) -> None:
    """
    在插件的独立库或 schema 上执行 Alembic 迁移
    :param plugin_id: 插件唯一标识
    :param instance_id: 实例标识，各实例在自己的库上执行迁移
    :param script_location: 插件迁移目录，需含 env.py 与 versions/
    :param revision: 目标版本，默认迁移到 head
    """
    bundle = db_manager.register_plugin(plugin_id, instance_id)
    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.attributes["target_metadata"] = bundle.metadata
    config.attributes["version_table_schema"] = bundle.schema

    with bundle.engine.connect() as connection:
        if bundle.schema:
            # 先确保插件 schema 存在，alembic_version 才能落到该 schema
            connection.execute(_pg_create_schema_ddl(bundle.schema))
        config.attributes["connection"] = connection
        command.upgrade(config, revision)
