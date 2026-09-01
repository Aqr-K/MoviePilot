"""插件自管理数据库——【接线】回归测试。

区别于 test_plugin_db_manager.py（验证 DbManager/per-plugin Base 本身），本文件验证
框架把插件 DB 钩子接到 PluginManager 生命周期与 setup 委托链上的「接线正确性」：

1. PluginManager.start() 加载插件时必须建表（启动/安装的主路径，而非仅在保存配置时）；
2. setup_plugin_database 走 db_manager.create_tables（PG 下先建 schema），而非直接
   metadata.create_all（后者在 PostgreSQL 下因 plugin_<id> schema 不存在而失败）。
"""


def test_start_invokes_setup_plugin_database(monkeypatch):
    """start() 加载插件后应调用 setup_plugin_database 建其自管理表（安装/重启主路径）。

    回归点：此前 start() 只调用 plugin.init_plugin，从不建表——声明了 provides_models 的
    插件要等用户在配置页保存（set_plugin_config → PluginManager.init_plugin）后才有表。
    """
    import app.db.plugin as plugin_mod
    from app.helper.plugin_manager import PluginManager

    captured = []
    monkeypatch.setattr(plugin_mod, "setup_plugin_database", lambda p: captured.append(p))

    class FakePlugin:
        plugin_name = "FakePlugin"
        plugin_order = 1
        plugin_version = "1.0.0"

        def init_plugin(self, config=None):
            self._inited = True

        def get_state(self) -> bool:
            return False

    pm = PluginManager()
    # 只测 DB 接线：屏蔽磁盘扫描、模块层注册与配置读取等无关副作用
    monkeypatch.setattr(pm, "_load_selective_plugins", lambda *a, **k: [FakePlugin])
    monkeypatch.setattr(pm, "_register_plugin_modules", lambda *a, **k: None)
    monkeypatch.setattr(pm, "get_plugin_config", lambda pid: {})
    try:
        pm.start("FakePlugin")
        assert len(captured) == 1, "start() 未为已加载插件调用 setup_plugin_database"
        assert isinstance(captured[0], FakePlugin)
    finally:
        # start() 对 get_state()=False 的插件调用 eventmanager.disable_event_handler，会把
        # FakePlugin 写入全局 eventmanager 单例的禁用集合；enable_event_handler 内部 discard，
        # 幂等清理以免污染共享单例、串扰其它测试（PluginManager/eventmanager 均为进程级单例）。
        from app.core.event import eventmanager
        eventmanager.enable_event_handler(FakePlugin)
        pm._plugins.pop("FakePlugin", None)
        pm._running_plugins.pop("FakePlugin", None)


def test_setup_plugin_database_delegates_to_create_tables(monkeypatch):
    """setup（create_all 路径）应委托 db_manager.create_tables，而非直接 metadata.create_all。

    回归点：create_tables 在 PostgreSQL 下会先 CREATE SCHEMA plugin_<id> 再建表；直接
    metadata.create_all(routed_engine) 会因该 schema 尚不存在而报错。委托即修复 PG 路径。
    """
    from sqlalchemy.orm import Mapped, mapped_column

    import app.db.plugin as plugin_mod
    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()

    class DelegModel(PluginBase):
        __tablename__ = "deleg"
        id: Mapped[int] = mapped_column(primary_key=True)

    # 插件类名须与 build_plugin_base 的 id 一致：框架按 __class__.__name__ 推导 plugin_id
    class DelegPlugin:
        def provides_models(self):
            return [DelegModel]

    called = {}
    real_create = db_manager.create_tables

    def spy(plugin_id):
        called["plugin_id"] = plugin_id
        return real_create(plugin_id)

    monkeypatch.setattr(db_manager, "create_tables", spy)
    try:
        plugin_mod.setup_plugin_database(DelegPlugin())
        assert called.get("plugin_id") == "DelegPlugin", \
            "setup_plugin_database 未委托 db_manager.create_tables（PG 建 schema 路径缺失）"
    finally:
        db_manager.drop_plugin("DelegPlugin")


def test_create_tables_postgresql_creates_schema_before_tables():
    """PG 下 create_tables 必须先 CREATE SCHEMA plugin_<id>、再在【同一带 schema 路由的连接】内建表。

    这是 Gap-2 修复真正针对的 PG 分支（manager.create_tables 的 if bundle.schema 路径）。
    用假 engine/metadata 直接执行该分支并断言「建 schema 先于建表、create_all 绑定同一连接」，
    避免 SQLite 委托测试代理 PG 正确性的盲区（默认 CI 无 PG，此分支否则零执行覆盖）。
    """
    from app.core.config import settings
    from app.db.manager import db_manager

    original = settings.DB_TYPE
    settings.DB_TYPE = "postgresql"
    try:
        bundle = db_manager.register_plugin("pg_schema_plugin")
        assert bundle.schema == "plugin_pg_schema_plugin"

        order = []

        class FakeConn:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, ddl):
                order.append(("execute", type(ddl).__name__))

        class FakeEngine:
            def begin(self):
                return FakeConn()

        class FakeMeta:
            def create_all(self, bind):
                order.append(("create_all", isinstance(bind, FakeConn)))

        bundle.engine = FakeEngine()
        bundle.metadata = FakeMeta()

        db_manager.create_tables("pg_schema_plugin")

        # 顺序与绑定：先 CreateSchema DDL，后 create_all 且 bind 为同一带路由的连接
        assert order == [("execute", "CreateSchema"), ("create_all", True)], order
    finally:
        db_manager.dispose("pg_schema_plugin")
        settings.DB_TYPE = original


def test_setup_plugin_database_is_idempotent_and_preserves_data():
    """重复 setup（每次启动/改配置都会触发）须幂等：第二次不报错、不重建、保留已有数据。

    覆盖「热重载保留数据」与「setup 幂等」——start() 与 init_plugin 都会调用 setup，已有数据的
    插件每次重启/改配置都重跑 setup，故须钉住其不清库。
    """
    from sqlalchemy import select
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import (
        build_plugin_base,
        setup_plugin_database,
        teardown_plugin_database,
    )

    PluginBase = build_plugin_base()

    class IdemModel(PluginBase):
        __tablename__ = "idem"
        id: Mapped[int] = mapped_column(primary_key=True)

    class IdemPlugin:
        def provides_models(self):
            return [IdemModel]

    plugin = IdemPlugin()
    try:
        setup_plugin_database(plugin)
        bundle = db_manager.get("IdemPlugin")
        with bundle.session() as session:
            session.add(IdemModel(id=1))
            session.commit()

        # 第二次 setup（模拟重启/改配置再次触发）——须幂等，不清库、不报错
        setup_plugin_database(plugin)
        with bundle.session() as session:
            ids = session.execute(select(IdemModel.id)).scalars().all()
        assert ids == [1], "重复 setup 破坏了已有数据（重复建表未保留数据）"
    finally:
        teardown_plugin_database("IdemPlugin")


def test_setup_plugin_database_dispatches_to_migrations_when_location_declared(monkeypatch):
    """声明 provides_migration_location 的插件，setup 应走 run_plugin_migrations，而非 create_tables。

    与 Gap-2 委托测试对称：覆盖「有迁移目录则走迁移链、不走 create_all」的分发，且无需经
    PluginManager.start 的磁盘扫描即可验证 start→setup→迁移分支的关键交互。
    """
    from sqlalchemy.orm import Mapped, mapped_column

    import app.db.plugin as plugin_mod
    import app.db.plugin_migration as mig_mod
    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()

    class MigModel(PluginBase):
        __tablename__ = "migd"
        id: Mapped[int] = mapped_column(primary_key=True)

    class MigDispatchPlugin:
        def provides_models(self):
            return [MigModel]

        def provides_migration_location(self):
            return "/tmp/mig_dispatch_location"

    ran = {}
    # setup 内是 `from app.db.plugin_migration import run_plugin_migrations`，故 patch 该模块属性
    monkeypatch.setattr(mig_mod, "run_plugin_migrations",
                        lambda pid, loc, *a, **k: ran.update(pid=pid, loc=loc))
    create_called = []
    monkeypatch.setattr(db_manager, "create_tables", lambda pid: create_called.append(pid))
    try:
        plugin_mod.setup_plugin_database(MigDispatchPlugin())
        assert ran.get("pid") == "MigDispatchPlugin", "声明迁移目录时未走 run_plugin_migrations"
        assert ran.get("loc") == "/tmp/mig_dispatch_location"
        assert create_called == [], "声明迁移目录时不应再走 create_tables（应走迁移链）"
    finally:
        db_manager.dispose("MigDispatchPlugin")


def test_orm_before_setup_raises_clear_error():
    """未经 setup 直接调用模型自会话 ORM，应抛清晰 RuntimeError（引导声明 provides_models）。

    钉死 _plugin_scoped_session 的错误契约：metadata.info 无 plugin_id 时把晦涩的 KeyError
    转为可操作提示。务必用【全新】Base，避免复用被其它测试污染过的 metadata.info。
    """
    import pytest
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.plugin import build_plugin_base

    PluginBase = build_plugin_base()  # 全新 Base，metadata.info 未被打 plugin_id

    class UnboundModel(PluginBase):
        __tablename__ = "unbound_item"
        id: Mapped[int] = mapped_column(primary_key=True)
        v: Mapped[str] = mapped_column(String)

    with pytest.raises(RuntimeError, match="尚未就绪"):
        UnboundModel.list()


def test_setup_rebinds_new_metadata_on_reload():
    """热重载：模块重导入产生【新】MetaData，setup 须把新 MetaData 重绑到同一容器并读到旧数据。

    回归点：attach_metadata 无条件重绑 bundle.metadata 与 metadata.info；若退化为「仅当为空才绑」，
    热重载后新模型 ORM 解析不到旧容器、读不到自己的数据，而幂等性测试仍全绿。
    """
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.manager import db_manager
    from app.db.plugin import build_plugin_base, setup_plugin_database, teardown_plugin_database

    def make_model():
        base = build_plugin_base()

        class ReloadModel(base):
            __tablename__ = "reload_item"
            id: Mapped[int] = mapped_column(primary_key=True)
            name: Mapped[str] = mapped_column(String)

        return ReloadModel

    class ReloadPlugin:
        models = []

        def provides_models(self):
            return list(ReloadPlugin.models)

    try:
        m1 = make_model()
        ReloadPlugin.models = [m1]
        setup_plugin_database(ReloadPlugin())
        m1(name="persisted").create()
        bundle1 = db_manager.get("ReloadPlugin")

        # 模拟热重载：新 build_plugin_base() → 新 MetaData → 新模型类（同表名、同 plugin_id）
        m2 = make_model()
        ReloadPlugin.models = [m2]
        setup_plugin_database(ReloadPlugin())

        assert m2.metadata is not m1.metadata          # 确为新 MetaData
        bundle2 = db_manager.get("ReloadPlugin")
        assert bundle2 is bundle1                        # 复用同一容器
        assert bundle2.metadata is m2.metadata           # 重绑到新 MetaData
        assert [r.name for r in m2.list()] == ["persisted"]  # 新模型 ORM 读到旧数据
    finally:
        teardown_plugin_database("ReloadPlugin")


def test_setup_handles_multiple_metadatas():
    """provides_models 跨多个 Base（多 MetaData）时，setup 应逐个建表+绑定，不静默漏建非 models[0]。"""
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.plugin import build_plugin_base, setup_plugin_database, teardown_plugin_database

    BaseA = build_plugin_base()
    BaseB = build_plugin_base()

    class ModelA(BaseA):
        __tablename__ = "multi_a"
        id: Mapped[int] = mapped_column(primary_key=True)
        v: Mapped[str] = mapped_column(String)

    class ModelB(BaseB):
        __tablename__ = "multi_b"
        id: Mapped[int] = mapped_column(primary_key=True)
        v: Mapped[str] = mapped_column(String)

    class MultiPlugin:
        def provides_models(self):
            return [ModelA, ModelB]

    try:
        setup_plugin_database(MultiPlugin())
        # 两张表都建好、ORM 都可用（含非 models[0] 的 ModelB）
        ModelA(v="a").create()
        ModelB(v="b").create()
        assert [m.v for m in ModelA.list()] == ["a"]
        assert [m.v for m in ModelB.list()] == ["b"]
    finally:
        teardown_plugin_database("MultiPlugin")


def test_teardown_clears_orm_anchor():
    """teardown 删库后，模型 ORM 应命中「未就绪」清晰报错，而非懒重建空容器/空库。"""
    import pytest
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.plugin import build_plugin_base, setup_plugin_database, teardown_plugin_database

    PluginBase = build_plugin_base()

    class AnchorModel(PluginBase):
        __tablename__ = "anchor_item"
        id: Mapped[int] = mapped_column(primary_key=True)
        v: Mapped[str] = mapped_column(String)

    class AnchorPlugin:
        def provides_models(self):
            return [AnchorModel]

    setup_plugin_database(AnchorPlugin())
    AnchorModel(v="x").create()
    teardown_plugin_database("AnchorPlugin")

    # 锚点已清除 → ORM 报清晰错误（而非懒重建空库）
    with pytest.raises(RuntimeError, match="尚未就绪"):
        AnchorModel.list()
