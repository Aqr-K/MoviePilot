"""插件数据库管理器（每插件独立容器）。

为「插件自管理、自维护、自调用、自会话管理」的数据库表提供框架层支持。
隔离模型（阶段1，SQLite）：每个插件拥有独立的 .db 文件 + 独立 Engine + 独立
ScopedSession，落在 ``PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db``，与核心
``user.db`` 物理隔离；卸载插件即删除该文件。PostgreSQL 的「每插件独立 schema」
（阶段2）将在此基础上以共享 Engine + schema_translate_map 扩展。

设计要点：
- 核心 Engine/会话仍由 app.db 维护，本管理器只负责「插件」这一类 owner。
- 注册表按 plugin_id 持有 PluginDatabase 实例（引擎/会话工厂/ScopedSession）。
- 与核心 app.db 完全解耦：插件表挂在各自的 MetaData 上，互不牵连建表/删表/迁移。
"""
from pathlib import Path
from typing import Dict, Optional

from sqlalchemy import Engine, NullPool, QueuePool, create_engine, event
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

from app.core.config import settings


class PluginDatabase:
    """单个插件的数据库容器：持有其独立引擎、会话工厂与线程安全 ScopedSession。"""

    def __init__(
        self,
        plugin_id: str,
        engine: Engine,
        session_factory: sessionmaker,
        scoped_session_factory: scoped_session,
        db_path: Optional[Path] = None,
        schema: Optional[str] = None,
        owns_engine: bool = True,
    ):
        self.plugin_id = plugin_id
        self.engine = engine
        self.session_factory = session_factory
        self.scoped_session = scoped_session_factory
        # SQLite：独立 .db 文件路径；PostgreSQL：None
        self.db_path = db_path
        # PostgreSQL：独立 schema 名 plugin_<id>；SQLite：None
        self.schema = schema
        # 是否独占引擎（SQLite 独立引擎=True 可 dispose；PG 复用核心引擎=False 不可 dispose）
        self.owns_engine = owns_engine
        # 由 build_plugin_base 注入：该插件所有模型挂载的独立 MetaData
        self.metadata = None

    def session(self):
        """新建一个绑定本插件引擎（含 schema 路由）的会话（调用方负责提交/关闭，可用 with 管理）。"""
        return self.session_factory()

    def dispose(self) -> None:
        """释放该插件的会话；仅当独占引擎时才释放连接池（PG 复用核心引擎，不可关闭）。"""
        if self.scoped_session is not None:
            self.scoped_session.remove()
        if self.owns_engine and self.engine is not None:
            self.engine.dispose()


def _plugin_db_path(plugin_id: str) -> Path:
    """插件独立 .db 文件路径：PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db。"""
    return settings.PLUGIN_DATA_PATH / plugin_id / f"{plugin_id}.db"


def _plugin_schema(plugin_id: str) -> str:
    """插件独立 PostgreSQL schema 名：plugin_<plugin_id>。"""
    return f"plugin_{plugin_id}"


def _pg_create_schema_ddl(schema: str) -> CreateSchema:
    """构造 CREATE SCHEMA IF NOT EXISTS <schema> 的 DDL（PostgreSQL）。"""
    return CreateSchema(schema, if_not_exists=True)


def _pg_drop_schema_ddl(schema: str) -> DropSchema:
    """构造 DROP SCHEMA IF EXISTS <schema> CASCADE 的 DDL（PostgreSQL）。"""
    return DropSchema(schema, cascade=True, if_exists=True)


def _register_sqlite_pragmas(engine: Engine) -> None:
    """为每个新连接设置 WAL/超时等 PRAGMA，沿用核心库的 SQLite 行为。"""

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection, _connection_record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            journal_mode = "WAL" if settings.DB_WAL_ENABLE else "DELETE"
            cursor.execute(f"PRAGMA journal_mode={journal_mode};")
            if settings.DB_WAL_ENABLE:
                cursor.execute(f"PRAGMA busy_timeout = {int(settings.DB_TIMEOUT * 1000)};")
        finally:
            cursor.close()


def _build_sqlite_engine(db_path: Path) -> Engine:
    """构建指向插件独立文件的 SQLite 引擎（沿用核心库的连接池/超时配置）。"""
    # 仅创建目录，文件由首次连接时创建
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connect_args = {"timeout": settings.DB_TIMEOUT}
    if settings.DB_WAL_ENABLE:
        connect_args["check_same_thread"] = False

    pool_class = NullPool if settings.DB_POOL_TYPE == "NullPool" else QueuePool
    db_kwargs = {
        "url": f"sqlite:///{db_path}",
        "pool_pre_ping": settings.DB_POOL_PRE_PING,
        "echo": settings.DB_ECHO,
        "poolclass": pool_class,
        "pool_recycle": settings.DB_POOL_RECYCLE,
        "connect_args": connect_args,
    }
    if pool_class == QueuePool:
        db_kwargs.update(
            {
                "pool_size": settings.DB_SQLITE_POOL_SIZE,
                "pool_timeout": settings.DB_POOL_TIMEOUT,
                "max_overflow": settings.DB_SQLITE_MAX_OVERFLOW,
            }
        )

    engine = create_engine(**db_kwargs)
    _register_sqlite_pragmas(engine)
    return engine


class DbManager:
    """插件数据库注册表：按 plugin_id 管理各插件的独立容器生命周期。"""

    def __init__(self):
        self._plugins: Dict[str, PluginDatabase] = {}

    def register_plugin(self, plugin_id: str) -> PluginDatabase:
        """注册（或返回已注册的）插件数据库容器。

        SQLite：独立 .db 文件 + 独立引擎；PostgreSQL：复用核心 Engine，
        按 plugin_<id> schema 路由（schema_translate_map），不独占连接池。
        """
        existing = self._plugins.get(plugin_id)
        if existing is not None:
            return existing
        if settings.DB_TYPE == "postgresql":
            bundle = self._build_postgresql_bundle(plugin_id)
        else:
            bundle = self._build_sqlite_bundle(plugin_id)
        self._plugins[plugin_id] = bundle
        return bundle

    @staticmethod
    def _build_sqlite_bundle(plugin_id: str) -> PluginDatabase:
        """SQLite：每插件独立 .db 文件 + 独立引擎/会话（独占引擎）。"""
        db_path = _plugin_db_path(plugin_id)
        engine = _build_sqlite_engine(db_path)
        session_factory = sessionmaker(bind=engine)
        return PluginDatabase(
            plugin_id=plugin_id,
            engine=engine,
            session_factory=session_factory,
            scoped_session_factory=scoped_session(session_factory),
            db_path=db_path,
            owns_engine=True,
        )

    @staticmethod
    def _build_postgresql_bundle(plugin_id: str) -> PluginDatabase:
        """PostgreSQL：复用核心 Engine，按 plugin_<id> schema 路由（不独占连接池）。"""
        # 延迟导入核心 Engine，避免与 app.db 顶层互相导入
        from app.db import Engine as CoreEngine

        schema = _plugin_schema(plugin_id)
        # execution_options 返回共享同一连接池的引擎外观，所有 SQL 把默认 schema 路由到插件 schema
        routed_engine = CoreEngine.execution_options(schema_translate_map={None: schema})
        session_factory = sessionmaker(bind=routed_engine)
        return PluginDatabase(
            plugin_id=plugin_id,
            engine=routed_engine,
            session_factory=session_factory,
            scoped_session_factory=scoped_session(session_factory),
            db_path=None,
            schema=schema,
            owns_engine=False,
        )

    def create_tables(self, plugin_id: str) -> None:
        """在插件独立库/ schema 中创建其 MetaData 上声明的所有表（启用/安装时调用）。"""
        bundle = self._plugins.get(plugin_id)
        if bundle is None:
            raise KeyError(f"插件未注册数据库容器: {plugin_id}")
        if bundle.metadata is None:
            return
        if bundle.schema:
            # PostgreSQL：先建 schema，再在 schema 路由下建表（engine 已带 schema_translate_map）
            with bundle.engine.begin() as conn:
                conn.execute(_pg_create_schema_ddl(bundle.schema))
                bundle.metadata.create_all(conn)
        else:
            bundle.metadata.create_all(bundle.engine)

    def drop_plugin(self, plugin_id: str) -> None:
        """卸载插件：释放容器并删除其独立 .db 文件（含 WAL 边车）。

        仅删除数据库文件本身，不触碰插件数据目录下的其它文件，目录清理由
        PluginManager 负责。未注册时静默返回。
        """
        bundle = self._plugins.pop(plugin_id, None)
        if bundle is None:
            return
        if bundle.schema:
            # PostgreSQL：DROP SCHEMA CASCADE（不删文件、不释放共享核心连接池）
            try:
                with bundle.engine.begin() as conn:
                    conn.execute(_pg_drop_schema_ddl(bundle.schema))
            finally:
                bundle.dispose()
            return
        # SQLite：释放独立引擎并删除 .db 文件（含 WAL 边车）
        bundle.dispose()
        db_path = bundle.db_path
        for path in (
            db_path,
            db_path.with_name(db_path.name + "-wal"),
            db_path.with_name(db_path.name + "-shm"),
        ):
            if path.exists():
                path.unlink()

    def get(self, plugin_id: str) -> Optional[PluginDatabase]:
        """获取已注册的插件数据库容器，未注册返回 None。"""
        return self._plugins.get(plugin_id)

    def is_registered(self, plugin_id: str) -> bool:
        """判断插件是否已注册数据库容器。"""
        return plugin_id in self._plugins

    def dispose(self, plugin_id: str) -> None:
        """释放并注销某插件的数据库容器（停服/卸载时调用）。"""
        bundle = self._plugins.pop(plugin_id, None)
        if bundle is not None:
            bundle.dispose()

    def dispose_all(self) -> None:
        """释放所有插件数据库容器（进程关闭时调用）。"""
        for plugin_id in list(self._plugins.keys()):
            self.dispose(plugin_id)


# 全局插件数据库管理器
db_manager = DbManager()
