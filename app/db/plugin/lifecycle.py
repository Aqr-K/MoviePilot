"""
插件数据库的建立与拆除。

由插件管理器在启用与删除插件数据时调用，按插件声明的 SPI 选择建表方式。
"""
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.db.plugin.migration import run_plugin_migrations
from app.db.plugin.registry import db_manager


def setup_plugin_database(plugin) -> None:
    """
    为插件建立其自管理的表

    声明了 ``provides_migration_location()`` 的插件走 Alembic 迁移链，否则按
    ``provides_models()`` 建表；两者都没有则空转。MetaData 从模型类反推而非沿用
    注册时的引用，使插件重载、容器重建之后仍能定位到正确的表集合。
    每个插件实例各建各的库，因此实例之间的自管理表与数据相互独立。

    :param plugin: 插件实例，其类名即为插件唯一标识
    """
    models = plugin.provides_models() or []
    location = None
    hook = getattr(plugin, "provides_migration_location", None)
    if hook:
        location = hook()
    plugin_id = getattr(plugin, "plugin_id", None) or plugin.__class__.__name__
    instance_id = getattr(plugin, "instance_id", None) or DEFAULT_INSTANCE_ID

    if location:
        bundle = db_manager.register_plugin(plugin_id, instance_id)
        if models:
            bundle.metadata = models[0].metadata
        run_plugin_migrations(plugin_id, location, instance_id=instance_id)
        return

    if not models:
        return
    bundle = db_manager.register_plugin(plugin_id, instance_id)
    bundle.metadata = models[0].metadata
    # 必须经 create_tables：它是唯一同时处理「PostgreSQL 建 schema」与「建表」的入口，
    # 直接 metadata.create_all 会绕过建 schema
    db_manager.create_tables(plugin_id, instance_id)


def teardown_plugin_database(plugin_id: str,
                             instance_id: str = DEFAULT_INSTANCE_ID) -> None:
    """
    删除插件实例的独立库，未注册时静默返回
    :param plugin_id: 插件唯一标识
    :param instance_id: 实例标识
    """
    db_manager.drop_plugin(plugin_id, instance_id)
