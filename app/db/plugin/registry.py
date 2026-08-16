"""
插件数据库注册表。

按插件 ID 管理各插件数据库容器的建立、建表、释放与删除。隔离模型分两种：
SQLite 每插件一个独立 .db 文件与独立引擎，落在
``PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db``；PostgreSQL 每插件一个独立
schema，共用核心引擎的连接池、仅以 schema_translate_map 路由。
"""
from pathlib import Path
from typing import Dict, Optional

from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

from app.db.engine import build_sqlite_engine, get_engine
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.db.plugin.container import PluginDatabase
from app.runtime.config import settings


def _container_key(plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> str:
    """
    插件实例的容器键

    默认实例退化为裸插件标识，使单实例插件的容器键与实例化之前一致。

    :param plugin_id: 插件唯一标识
    :param instance_id: 实例标识
    :return: 容器键
    """
    if instance_id == DEFAULT_INSTANCE_ID:
        return plugin_id
    return f"{plugin_id}@{instance_id}"


def _plugin_db_path(plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> Path:
    """
    插件实例的独立库文件路径

    默认实例沿用插件目录下的库文件，使实例化之前的存量数据原地可用；分身各自落在
    instances/<instance_id> 之下，因此实例之间的表与数据互不可见。

    :param plugin_id: 插件唯一标识
    :param instance_id: 实例标识
    :return: 该实例独占的库文件路径
    """
    plugin_root = settings.PLUGIN_DATA_PATH / plugin_id
    if instance_id == DEFAULT_INSTANCE_ID:
        return plugin_root / f"{plugin_id}.db"
    return plugin_root / "instances" / instance_id / f"{plugin_id}.db"


def _plugin_schema(plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> str:
    """
    插件实例的独立 PostgreSQL schema 名

    :param plugin_id: 插件唯一标识
    :param instance_id: 实例标识
    :return: 默认实例为 plugin_<plugin_id>，分身为 plugin_<plugin_id>__<instance_id>
    """
    if instance_id == DEFAULT_INSTANCE_ID:
        return f"plugin_{plugin_id}"
    return f"plugin_{plugin_id}__{instance_id}"


def _pg_create_schema_ddl(schema: str) -> CreateSchema:
    """
    构造 CREATE SCHEMA IF NOT EXISTS 的 DDL
    :param schema: schema 名
    :return: 可执行的 DDL 元素
    """
    return CreateSchema(schema, if_not_exists=True)


def _pg_drop_schema_ddl(schema: str) -> DropSchema:
    """
    构造 DROP SCHEMA IF EXISTS ... CASCADE 的 DDL
    :param schema: schema 名
    :return: 可执行的 DDL 元素
    """
    return DropSchema(schema, cascade=True, if_exists=True)


class DbManager:
    """
    插件数据库注册表，按插件实例管理各容器的生命周期

    同一插件的每个实例各持一个容器：SQLite 下是各自的库文件，PostgreSQL 下是各自的
    schema，因此实例之间的自管理表相互独立。
    """

    def __init__(self):
        self._plugins: Dict[str, PluginDatabase] = {}

    def register_plugin(self, plugin_id: str,
                        instance_id: str = DEFAULT_INSTANCE_ID) -> PluginDatabase:
        """
        注册插件实例的数据库容器，已注册时直接返回既有容器
        :param plugin_id: 插件唯一标识
        :param instance_id: 实例标识
        :return: 该实例的数据库容器
        """
        key = _container_key(plugin_id, instance_id)
        existing = self._plugins.get(key)
        if existing is not None:
            return existing
        if settings.DB_TYPE.lower() == "postgresql":
            bundle = self._build_postgresql_bundle(plugin_id, instance_id)
        else:
            bundle = self._build_sqlite_bundle(plugin_id, instance_id)
        self._plugins[key] = bundle
        return bundle

    @staticmethod
    def _build_sqlite_bundle(plugin_id: str,
                             instance_id: str = DEFAULT_INSTANCE_ID) -> PluginDatabase:
        """
        建立 SQLite 容器：独立库文件与独占引擎
        :param plugin_id: 插件唯一标识
        :return: 该插件的数据库容器
        """
        db_path = _plugin_db_path(plugin_id, instance_id)
        # 只建目录，库文件由首次连接时创建
        db_path.parent.mkdir(parents=True, exist_ok=True)
        engine = build_sqlite_engine(f"sqlite:///{db_path}")
        session_factory = sessionmaker(bind=engine)
        return PluginDatabase(
            plugin_id=plugin_id,
            instance_id=instance_id,
            engine=engine,
            session_factory=session_factory,
            scoped_session_factory=scoped_session(session_factory),
            db_path=db_path,
            owns_engine=True,
        )

    @staticmethod
    def _build_postgresql_bundle(plugin_id: str,
                                 instance_id: str = DEFAULT_INSTANCE_ID) -> PluginDatabase:
        """
        建立 PostgreSQL 容器：复用核心引擎并按插件 schema 路由
        :param plugin_id: 插件唯一标识
        :return: 该插件的数据库容器
        """
        schema = _plugin_schema(plugin_id, instance_id)
        # execution_options 返回的是共享同一连接池的引擎外观，不是新引擎；
        # 它把所有 SQL 的默认 schema 路由到插件 schema，因此不独占连接池
        routed_engine = get_engine().execution_options(schema_translate_map={None: schema})
        session_factory = sessionmaker(bind=routed_engine)
        return PluginDatabase(
            plugin_id=plugin_id,
            instance_id=instance_id,
            engine=routed_engine,
            session_factory=session_factory,
            scoped_session_factory=scoped_session(session_factory),
            db_path=None,
            schema=schema,
            owns_engine=False,
        )

    def create_tables(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> None:
        """
        在插件的独立库或 schema 中创建其 MetaData 上声明的全部表
        :param plugin_id: 插件唯一标识
        """
        bundle = self._plugins.get(_container_key(plugin_id, instance_id))
        if bundle is None:
            raise KeyError(f"插件未注册数据库容器: {plugin_id}")
        if bundle.metadata is None:
            return
        if bundle.schema:
            # 必须在同一事务连接上先建 schema 再建表：绑定到 engine 建表时目标
            # schema 尚未创建，PostgreSQL 会直接报 schema does not exist
            with bundle.engine.begin() as conn:
                conn.execute(_pg_create_schema_ddl(bundle.schema))
                bundle.metadata.create_all(conn)
        else:
            bundle.metadata.create_all(bundle.engine)

    def drop_plugin(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> None:
        """
        删除插件的独立库：释放容器并删除库文件或 schema，未注册时静默返回

        只删数据库本身，插件数据目录下的其它文件由插件管理器负责清理。
        :param plugin_id: 插件唯一标识
        """
        bundle = self._plugins.pop(_container_key(plugin_id, instance_id), None)
        if bundle is None:
            return
        if bundle.schema:
            try:
                with bundle.engine.begin() as conn:
                    conn.execute(_pg_drop_schema_ddl(bundle.schema))
            finally:
                bundle.dispose()
            return
        bundle.dispose()
        db_path = bundle.db_path
        # WAL 边车与主库文件同去同留，留下会让下次建库读到半截状态
        for path in (
                db_path,
                db_path.with_name(db_path.name + "-wal"),
                db_path.with_name(db_path.name + "-shm"),
        ):
            if path.exists():
                path.unlink()

    def get(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> Optional[PluginDatabase]:
        """
        获取已注册的插件数据库容器
        :param plugin_id: 插件唯一标识
        :return: 数据库容器，未注册时为 None
        """
        return self._plugins.get(_container_key(plugin_id, instance_id))

    def is_registered(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> bool:
        """
        判断插件是否已注册数据库容器
        :param plugin_id: 插件唯一标识
        :return: 是否已注册
        """
        return _container_key(plugin_id, instance_id) in self._plugins

    def dispose(self, plugin_id: str, instance_id: str = DEFAULT_INSTANCE_ID) -> None:
        """
        释放并注销插件的数据库容器，只断连接、保留数据
        :param plugin_id: 插件唯一标识
        """
        bundle = self._plugins.pop(_container_key(plugin_id, instance_id), None)
        if bundle is not None:
            bundle.dispose()

    def dispose_all(self) -> None:
        """
        释放全部插件数据库容器，供进程关停调用
        """
        for key in list(self._plugins.keys()):
            bundle = self._plugins.pop(key, None)
            if bundle is not None:
                bundle.dispose()


# 全局插件数据库管理器
db_manager = DbManager()
