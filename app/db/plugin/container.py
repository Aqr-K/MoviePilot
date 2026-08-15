"""
插件数据库容器。

持有单个插件的引擎、会话工厂与线程安全会话注册表，是「插件自会话管理」的载体。
"""
from pathlib import Path
from typing import Optional

from sqlalchemy import Engine
from sqlalchemy.orm import scoped_session, sessionmaker


class PluginDatabase:
    """
    单个插件的数据库容器，持有其引擎、会话工厂与线程安全 ScopedSession
    """

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
        """
        :param plugin_id: 插件唯一标识
        :param engine: 该插件读写所用的引擎
        :param session_factory: 绑定该引擎的会话工厂
        :param scoped_session_factory: 线程局部的会话注册表
        :param db_path: SQLite 下的独立库文件路径，PostgreSQL 下为 None
        :param schema: PostgreSQL 下的独立 schema 名，SQLite 下为 None
        :param owns_engine: 是否独占引擎，决定 dispose 能否释放连接池
        """
        self.plugin_id = plugin_id
        self.engine = engine
        self.session_factory = session_factory
        self.scoped_session = scoped_session_factory
        self.db_path = db_path
        self.schema = schema
        self.owns_engine = owns_engine
        # 该插件全部模型挂载的独立 MetaData，由 build_plugin_base 注入
        self.metadata = None

    def session(self):
        """
        新建一个绑定本插件引擎（含 schema 路由）的会话，调用方负责提交与关闭
        :return: Session
        """
        return self.session_factory()

    def dispose(self) -> None:
        """
        释放本插件的会话，并在独占引擎时一并释放连接池

        PostgreSQL 下引擎是核心引擎的外观、连接池全站共享，释放它会让所有其它
        使用者的连接一并失效，因此只有独占引擎时才 dispose。
        """
        if self.scoped_session is not None:
            self.scoped_session.remove()
        if self.owns_engine and self.engine is not None:
            self.engine.dispose()
