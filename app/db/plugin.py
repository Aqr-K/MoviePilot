"""per-plugin 声明式 Base 构建（插件自管理表的入口）。

每个插件通过 ``build_plugin_base(plugin_id)`` 获得一个拥有**独立 MetaData**
的声明式 Base，插件的所有模型继承它即可。这样：

- 插件表挂在各自的 MetaData 上，与核心 ``app.db.Base`` 及其它插件完全隔离；
- 建表/删表/迁移互不牵连（核心的 ``create_all`` 不会看到插件表，反之亦然）；
- 配合 ``db_manager`` 的「每插件独立容器」，落到插件专属的 .db 文件 / schema。
"""
from typing import Type

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

from app.db.manager import db_manager


def build_plugin_base(plugin_id: str) -> Type[DeclarativeBase]:
    """为插件构建独立 MetaData 的声明式 Base，并登记到其数据库容器。

    :param plugin_id: 插件唯一标识（同时决定其独立库路径/ schema 名）。
    :return: 一个新的 ``DeclarativeBase`` 子类，插件模型应继承它。
    """
    bundle = db_manager.register_plugin(plugin_id)
    plugin_metadata = MetaData()

    class PluginBase(DeclarativeBase):
        # 覆盖默认 MetaData，使该 Base 下的模型与核心/其它插件隔离
        metadata = plugin_metadata

    # 让 db_manager.create_tables 能定位到该插件需要创建的表集合
    bundle.metadata = plugin_metadata
    return PluginBase


def setup_plugin_database(plugin) -> None:
    """为声明了自管理模型的插件在其独立库中建表。

    由 PluginManager 在启动/启用插件时调用。仅当插件 ``provides_models()`` 返回
    非空模型类列表时才建表；从模型类反推 MetaData，使重载/重注册后仍能正确建表。

    :param plugin: 插件实例，需实现 ``provides_models()`` 且其 ``__class__.__name__``
        即为 plugin_id（与 build_plugin_base 一致）。
    """
    models = plugin.provides_models() or []
    location = None
    hook = getattr(plugin, "provides_migration_location", None)
    if hook:
        location = hook()
    plugin_id = plugin.__class__.__name__

    # 声明了迁移目录 → 走 Alembic 迁移链（可选接入）；否则默认 create_all
    if location:
        bundle = db_manager.register_plugin(plugin_id)
        if models:
            bundle.metadata = models[0].metadata
        from app.db.plugin_migration import run_plugin_migrations
        run_plugin_migrations(plugin_id, location)
        return

    if not models:
        return
    bundle = db_manager.register_plugin(plugin_id)
    bundle.metadata = models[0].metadata
    # 经 db_manager.create_tables 建表：SQLite 直接建表；PostgreSQL 先 CREATE SCHEMA
    # 再在 schema 路由的事务连接上建表（直接 metadata.create_all 会绕过建 schema）。
    db_manager.create_tables(plugin_id)


def teardown_plugin_database(plugin_id: str) -> None:
    """卸载插件时删除其独立库（释放容器并删除 .db 文件）。

    由 PluginManager 在删除插件数据时调用；未注册时静默返回。
    """
    db_manager.drop_plugin(plugin_id)
