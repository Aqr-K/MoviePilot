"""插件自管理迁移（阶段3 骨架：per-plugin Alembic env + upgrade 运行器，可选接入）。

设计：
- 插件迁移目录（如 ``app/plugins/<id>/database``）放置 versions/ 与本模块提供的
  通用 ``env.py`` 模板（用 ``write_plugin_alembic_env`` 写入即可，无需手写）。
- 运行器 ``run_plugin_migrations`` 把【插件容器的连接 + Base.metadata + 版本表 schema】
  注入 Alembic Config.attributes，由 env 模板读取后执行 ``upgrade``。
- 版本隔离天然成立：SQLite 每插件独立 .db、PostgreSQL 每插件独立 schema，
  ``alembic_version`` 各自独立（PG 经 ``version_table_schema`` 落到插件 schema）。
- 默认仍走 ``create_all``（见 app.db.plugin.setup_plugin_database）；声明
  ``_PluginBase.provides_migration_location()`` 的插件才改走迁移链。
"""
from pathlib import Path
from typing import Union

# 通用 env.py 模板：由运行器经 config.attributes 注入连接/元数据/版本表 schema
PLUGIN_ALEMBIC_ENV = '''"""插件自管理迁移的通用 Alembic env（由 app.db.plugin_migration 运行器注入连接）。"""
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
    """将通用 env.py 模板写入插件迁移目录（幂等覆盖），返回 env.py 路径。

    插件只需维护 ``script_location/versions/*.py`` 迁移脚本，env.py 由本函数生成。
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
) -> None:
    """在插件独立库/ schema 上执行 Alembic 迁移到指定版本（默认 head）。

    绑定插件容器的引擎连接；PostgreSQL 下先确保插件 schema 存在，并把
    ``alembic_version`` 落到插件 schema（version_table_schema）。
    """
    from alembic import command
    from alembic.config import Config

    from app.db.manager import _pg_create_schema_ddl, db_manager

    bundle = db_manager.register_plugin(plugin_id)
    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.attributes["target_metadata"] = bundle.metadata
    config.attributes["version_table_schema"] = bundle.schema

    with bundle.engine.connect() as connection:
        if bundle.schema:
            # 确保插件 schema 存在，alembic_version 才能落到该 schema
            connection.execute(_pg_create_schema_ddl(bundle.schema))
        config.attributes["connection"] = connection
        command.upgrade(config, revision)
