"""插件自管理数据库（每插件独立容器）—— DbManager 与 per-plugin Base 测试。

隔离模型：SQLite 每插件一个独立 .db 文件（独立 engine + ScopedSession），
卸载即删文件。本测试覆盖：注册、建表、会话读写与物理隔离、卸载清理。
插件用 build_plugin_base + bundle.session() 即可完整 ORM 读写（即「自会话管理」）。
"""


def test_register_plugin_builds_isolated_sqlite_engine():
    """注册插件应得到指向 plugins/<id>/<id>.db 的独立引擎，且不复用核心引擎。"""
    from app.core.config import settings
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager

    bundle = db_manager.register_plugin("demo_plugin")
    try:
        expected = settings.PLUGIN_DATA_PATH / "demo_plugin" / "demo_plugin.db"
        # 引擎指向插件独立文件
        assert str(expected) in str(bundle.engine.url)
        # 不是核心引擎（物理隔离）
        assert bundle.engine is not CoreEngine
    finally:
        db_manager.dispose("demo_plugin")


def test_plugin_owns_isolated_table_for_read_write():
    """插件用 per-plugin Base 定义真实表，应能在自己的独立库建表/读写，且与核心库物理隔离。"""
    from sqlalchemy import String, inspect, select
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db import Base as CoreBase
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()

    class Note(PluginBase):
        __tablename__ = "note"
        id: Mapped[int] = mapped_column(primary_key=True)
        text: Mapped[str] = mapped_column(String)

    try:
        # 注册容器 + 绑定 plugin_id 到 MetaData（无参 build_plugin_base 不再代建容器），再建表
        db_manager.attach_metadata("note_plugin", Note.metadata)
        db_manager.create_tables("note_plugin")
        bundle = db_manager.get("note_plugin")

        # 写入并读取（使用插件自己的会话）
        with bundle.session() as session:
            session.add(Note(text="hello"))
            session.commit()
        with bundle.session() as session:
            texts = session.execute(select(Note.text)).scalars().all()
            assert texts == ["hello"]

        # 物理隔离：插件表不在核心 MetaData，也不在核心 user.db
        assert "note" not in CoreBase.metadata.tables
        assert "note" not in inspect(CoreEngine).get_table_names()
        # 插件库里确实有该表
        assert "note" in inspect(bundle.engine).get_table_names()
    finally:
        db_manager.dispose("note_plugin")


def test_drop_plugin_removes_db_file_and_unregisters():
    """卸载插件应删除其独立 .db 文件（含 WAL 边车）并注销容器。"""
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()

    class Item(PluginBase):
        __tablename__ = "item"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(String)

    db_manager.attach_metadata("temp_plugin", Item.metadata)
    db_manager.create_tables("temp_plugin")
    bundle = db_manager.get("temp_plugin")
    db_path = bundle.db_path
    # 建表后写一行以确保物理文件生成
    with bundle.session() as session:
        session.add(Item(name="x"))
        session.commit()
    assert db_path.exists()

    # 卸载：删文件 + 注销
    db_manager.drop_plugin("temp_plugin")

    assert not db_path.exists()
    assert db_path.with_name(db_path.name + "-wal").exists() is False
    assert db_manager.get("temp_plugin") is None
    assert db_manager.is_registered("temp_plugin") is False


def test_setup_and_teardown_plugin_database_via_models_hook():
    """声明了 provides_models 的插件应能经 setup 建表、teardown 删库。"""
    from sqlalchemy import String, inspect
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import (
        build_plugin_base,
        setup_plugin_database,
        teardown_plugin_database,
    )

    PluginBase = build_plugin_base()

    class Record(PluginBase):
        __tablename__ = "record"
        id: Mapped[int] = mapped_column(primary_key=True)
        val: Mapped[str] = mapped_column(String)

    class HookPlugin:
        # 框架按 __class__.__name__ 自动取 plugin_id（无需手传），故类名即 plugin_id
        def provides_models(self):
            return [Record]

    plugin = HookPlugin()
    db_path = None
    try:
        setup_plugin_database(plugin)
        bundle = db_manager.get("HookPlugin")
        db_path = bundle.db_path
        assert "record" in inspect(bundle.engine).get_table_names()
        assert db_path.exists()
    finally:
        teardown_plugin_database("HookPlugin")
    assert db_path is not None and not db_path.exists()
    assert db_manager.get("HookPlugin") is None


def test_pluginbase_models_hook_and_db_accessor():
    """_PluginBase 默认 provides_models 为空；get_plugin_db 返回按类名注册的独立容器。"""
    from app.db.manager import db_manager
    from app.plugins import _PluginBase

    class DummyPlugin(_PluginBase):
        def init_plugin(self, config=None):
            pass

        def get_state(self) -> bool:
            return False

        def stop_service(self):
            pass

        def get_api(self):
            return []

        def get_form(self):
            return None, {}

        def get_page(self):
            return []

    # 绕过 _PluginBase 重型 __init__（实例化多个 Oper/单例），仅验证待测方法
    plugin = DummyPlugin.__new__(DummyPlugin)
    try:
        assert plugin.provides_models() == []
        bundle = plugin.get_plugin_db()
        assert bundle.plugin_id == "DummyPlugin"
        assert db_manager.is_registered("DummyPlugin")
    finally:
        db_manager.dispose("DummyPlugin")


def test_register_plugin_postgresql_reuses_shared_engine():
    """PG 模式下插件复用核心 Engine 并按 plugin_<id> schema 路由，不独占连接池/文件。"""
    from app.core.config import settings
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager

    original = settings.DB_TYPE
    settings.DB_TYPE = "postgresql"
    try:
        bundle = db_manager.register_plugin("pg_plugin")
        # 独立 schema，无独立文件
        assert bundle.schema == "plugin_pg_plugin"
        assert bundle.db_path is None
        # 不独占引擎（共享核心连接池）
        assert bundle.owns_engine is False
        # 引擎带 schema 路由（execution_options）
        opts = bundle.engine.get_execution_options()
        assert opts.get("schema_translate_map") == {None: "plugin_pg_plugin"}
        # 底层连接池即核心引擎的连接池（共享）
        assert bundle.engine.pool is CoreEngine.pool
    finally:
        db_manager.dispose("pg_plugin")
        settings.DB_TYPE = original


def test_dispose_postgresql_plugin_keeps_shared_engine_alive():
    """PG 模式 dispose 插件容器不得释放共享核心连接池（仅清理会话）。"""
    from sqlalchemy import text

    from app.core.config import settings
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager

    original = settings.DB_TYPE
    settings.DB_TYPE = "postgresql"
    try:
        db_manager.register_plugin("pg_plugin2")
        db_manager.dispose("pg_plugin2")
        # 共享核心引擎 dispose 后仍可用（连接池未被插件容器关闭）
        with CoreEngine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1
    finally:
        settings.DB_TYPE = original


def test_postgresql_schema_ddl_statements():
    """PG 建/删 schema 的 DDL 应生成正确语句（CREATE SCHEMA IF NOT EXISTS / DROP SCHEMA CASCADE）。"""
    from sqlalchemy.dialects import postgresql

    from app.db.manager import _pg_create_schema_ddl, _pg_drop_schema_ddl

    create_sql = str(_pg_create_schema_ddl("plugin_x").compile(dialect=postgresql.dialect()))
    drop_sql = str(_pg_drop_schema_ddl("plugin_x").compile(dialect=postgresql.dialect()))

    assert "CREATE SCHEMA" in create_sql
    assert "IF NOT EXISTS" in create_sql
    assert "plugin_x" in create_sql
    assert "DROP SCHEMA" in drop_sql
    assert "CASCADE" in drop_sql
    assert "plugin_x" in drop_sql


def test_run_plugin_migrations_applies_alembic_upgrade_on_sqlite():
    """阶段3 骨架：插件经 Alembic env 模板 + 运行器在自己的独立库执行迁移建表。"""
    import shutil
    import tempfile
    from pathlib import Path

    from sqlalchemy import inspect

    from app.db.manager import db_manager
    from app.db.plugin_migration import (
        run_plugin_migrations,
        write_plugin_alembic_env,
    )

    plugin_id = "mig_plugin"
    db_manager.register_plugin(plugin_id)
    tmp = Path(tempfile.mkdtemp())
    try:
        # 写入可复用 env.py 模板 + 一个最小迁移脚本
        write_plugin_alembic_env(tmp)
        versions = tmp / "versions"
        versions.mkdir(exist_ok=True)
        (versions / "0001_init.py").write_text(
            'revision = "0001"\n'
            "down_revision = None\n"
            "branch_labels = None\n"
            "depends_on = None\n"
            "from alembic import op\n"
            "import sqlalchemy as sa\n\n"
            "def upgrade():\n"
            "    op.create_table('mig_demo', sa.Column('id', sa.Integer, primary_key=True))\n\n"
            "def downgrade():\n"
            "    op.drop_table('mig_demo')\n"
        )
        run_plugin_migrations(plugin_id, tmp)
        bundle = db_manager.get(plugin_id)
        names = inspect(bundle.engine).get_table_names()
        assert "mig_demo" in names
        assert "alembic_version" in names
    finally:
        db_manager.drop_plugin(plugin_id)
        shutil.rmtree(tmp, ignore_errors=True)


def test_dispose_keeps_data_file_drop_removes_it():
    """卸载/停用语义：dispose 只释放连接、保留数据文件；唯有 drop（明确删除）才删库。"""
    from sqlalchemy import String, inspect
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()

    class Row(PluginBase):
        __tablename__ = "row"
        id: Mapped[int] = mapped_column(primary_key=True)
        v: Mapped[str] = mapped_column(String)

    db_manager.attach_metadata("keep_plugin", Row.metadata)
    db_manager.create_tables("keep_plugin")
    bundle = db_manager.get("keep_plugin")
    db_path = bundle.db_path
    with bundle.session() as session:
        session.add(Row(v="x"))
        session.commit()
    assert db_path.exists()

    # dispose：释放连接、移出注册表，但【保留】数据文件
    db_manager.dispose("keep_plugin")
    assert db_manager.get("keep_plugin") is None
    assert db_path.exists()

    # 重新注册并读回 → 数据仍在（证明 dispose 没删库）
    db_manager.register_plugin("keep_plugin")
    rebound = db_manager.get("keep_plugin")
    assert "row" in inspect(rebound.engine).get_table_names()

    # 唯有 drop（明确删除）才删文件
    db_manager.drop_plugin("keep_plugin")
    assert not db_path.exists()


def test_setup_plugin_database_uses_migrations_when_location_declared():
    """声明了 provides_migration_location 的插件，setup 应走 Alembic 迁移（而非 create_all）。"""
    import shutil
    import tempfile
    from pathlib import Path

    from sqlalchemy import inspect
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import (
        build_plugin_base,
        setup_plugin_database,
        teardown_plugin_database,
    )
    from app.db.plugin_migration import write_plugin_alembic_env

    PluginBase = build_plugin_base()

    class Thing(PluginBase):
        __tablename__ = "thing"
        id: Mapped[int] = mapped_column(primary_key=True)

    tmp = Path(tempfile.mkdtemp())
    write_plugin_alembic_env(tmp)
    (tmp / "versions").mkdir(exist_ok=True)
    (tmp / "versions" / "0001_init.py").write_text(
        'revision = "0001"\n'
        "down_revision = None\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        "def upgrade():\n"
        "    op.create_table('thing', sa.Column('id', sa.Integer, primary_key=True))\n\n"
        "def downgrade():\n"
        "    op.drop_table('thing')\n"
    )

    class MigHookPlugin:
        def provides_models(self):
            return [Thing]

        def provides_migration_location(self):
            return tmp

    try:
        setup_plugin_database(MigHookPlugin())
        bundle = db_manager.get("MigHookPlugin")
        names = inspect(bundle.engine).get_table_names()
        assert "thing" in names
        # alembic_version 存在 → 证明走的是迁移链而非 create_all
        assert "alembic_version" in names
    finally:
        teardown_plugin_database("MigHookPlugin")
        shutil.rmtree(tmp, ignore_errors=True)


def test_plugin_model_self_session_orm():
    """模型自会话 ORM：create/get/list/update/delete 绑定本插件独立库，自动取会话/提交/清理。

    验证「无需手传 id、无需手搓 session」的接口：plugin_id 由 setup 从插件实例类名自动判断并
    绑定到模型 MetaData，模型 ORM 据此自解析会话。update 用 merge（脱管对象按主键 UPDATE）。
    """
    from sqlalchemy import String

    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import (
        build_plugin_base,
        setup_plugin_database,
        teardown_plugin_database,
    )

    PluginBase = build_plugin_base()

    class OrmModel(PluginBase):
        __tablename__ = "orm_item"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(String)

    class OrmPlugin:
        # 类名即 plugin_id（框架自动判断，无手传）
        def provides_models(self):
            return [OrmModel]

    try:
        setup_plugin_database(OrmPlugin())   # 建表 + 把 plugin_id 绑定到 MetaData

        # create：返回带自增主键的对象（expire_on_commit=False，主键直接可读）
        obj = OrmModel(name="a").create()
        assert isinstance(obj.id, int) and obj.id > 0
        OrmModel(name="b").create()

        # list / get
        assert sorted(m.name for m in OrmModel.list()) == ["a", "b"]
        assert OrmModel.get(obj.id).name == "a"

        # update：脱管对象经 add 按主键 UPDATE（self 本身成持久对象，无 merge 分叉）
        obj.update({"name": "a2"})
        assert OrmModel.get(obj.id).name == "a2"

        # get → update（跨会话：上一会话已关闭、对象脱管，再 update 须走 UPDATE 而非 INSERT 冲突）
        fetched = OrmModel.get(obj.id)
        fetched.update({"name": "a3"})
        assert OrmModel.get(obj.id).name == "a3"

        # to_dict
        d = OrmModel.get(obj.id).to_dict()
        assert d["name"] == "a3" and "id" in d

        # delete
        OrmModel.delete(obj.id)
        assert OrmModel.get(obj.id) is None
        assert [m.name for m in OrmModel.list()] == ["b"]

        # truncate：清空全表
        OrmModel.truncate()
        assert OrmModel.list() == []
    finally:
        teardown_plugin_database("OrmPlugin")
