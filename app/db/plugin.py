"""per-plugin 声明式 Base 构建（插件自管理表的入口）。

每个插件通过 ``build_plugin_base()`` 获得一个拥有**独立 MetaData**、且自带**自会话 ORM**
的声明式 Base，插件模型继承它即可：

- **无需手传 plugin_id**：框架统一从插件实例 ``__class__.__name__`` 自动判断（消除手传/误传），
  ``provides_models()`` 即「向框架注册本插件 MetaData」的接口；
- 插件表挂在各自独立 MetaData 上，与核心 ``app.db.Base`` 及其它插件完全隔离；
- 模型自带 ``create/get/list/update/delete/truncate`` 等自会话 ORM（每次调用一段独立私有会话，
  自动取会话/提交/回滚/关闭），读写无需手搓 ``session()``。

会话如何解析（无 id 也不靠手传）：框架在 ``setup_plugin_database`` 时把 plugin_id 打到该插件
模型 MetaData 的 ``info['plugin_id']`` 上，模型 ORM 据此 O(1) 定位本插件容器（``db_manager``）。
"""
from typing import List, Type

from sqlalchemy import MetaData, delete as sa_delete, inspect, select
from sqlalchemy.orm import DeclarativeBase

from app.db.manager import db_manager


class PluginModelMixin:
    """插件模型的自会话 ORM 混入：自动解析本插件独立库的会话并管理事务/清理。

    会话解析不依赖任何手传 id——模型的 MetaData 在框架 setup 时被打上 ``info['plugin_id']``
    （= 插件类名），ORM 方法据此定位插件容器，故插件作者无需、也无从误传 id。

    **每个 ORM 调用都用一段独立私有会话**（一段自洽事务：取会话 → 操作 → commit/rollback →
    close），互不影响、不共享线程局部状态。需要把多次读写并入【同一事务】时，请改用
    ``get_plugin_db().session()`` 在一个 with 块内操作。

    约束（作为参考样板，复制/扩展时注意）：
    - **主键属性须命名为 ``id``**：get/delete/update 按 ``id`` 主键定位（与核心 ``app.db.Base`` 一致）；
    - **返回对象是「脱管」的**：标量列可读（sessionmaker ``expire_on_commit=False``），但不可再触发
      惰性关系加载（会 ``DetachedInstanceError``）——需要关系数据请在 ``session()`` 的 with 块内预加载；
    - **delete/truncate 用 Core 级批量 DELETE**：不触发 ORM 关系级联与 before/after_delete 事件
      （如需级联请在外键上配置 DB 级 ON DELETE CASCADE，或在 ``session()`` 内 ``session.delete(obj)``）。
    """

    @classmethod
    def _plugin_bundle(cls):
        """解析本插件独立库容器（经模型 MetaData.info 上的 plugin_id 定位）。"""
        plugin_id = cls.metadata.info.get("plugin_id")
        if not plugin_id:
            raise RuntimeError(
                f"插件模型 {cls.__name__} 的数据库尚未就绪：请确保该模型已由插件 "
                f"provides_models() 声明，且插件已被框架加载（PluginManager.start → "
                f"setup_plugin_database 会自动建表并把 plugin_id 绑定到模型 MetaData）。"
            )
        return db_manager.register_plugin(plugin_id)

    def create(self):
        """插入本对象并提交，返回自身（脱管但标量列可读，含自增主键）。"""
        session = type(self)._plugin_bundle().session()
        try:
            session.add(self)
            session.commit()
            return self
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @classmethod
    def get(cls, rid):
        """按主键 id 取单条，不存在返回 None。"""
        session = cls._plugin_bundle().session()
        try:
            return session.execute(select(cls).where(cls.id == rid)).scalars().first()
        finally:
            session.close()

    @classmethod
    def list(cls) -> list:
        """取本表全部记录。"""
        session = cls._plugin_bundle().session()
        try:
            return list(session.execute(select(cls)).scalars().all())
        finally:
            session.close()

    def update(self, payload: dict):
        """按字典就地更新本对象字段并提交。

        对齐核心 Base：脱管对象经 ``add`` 重新纳入会话（带持久主键 → flush 为 UPDATE），
        使 self 本身成为持久对象、无 merge 分叉；要求对象已有主键（否则为非持久态，不更新）。
        """
        session = type(self)._plugin_bundle().session()
        try:
            for key, value in payload.items():
                setattr(self, key, value)
            if inspect(self).detached:
                session.add(self)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @classmethod
    def delete(cls, rid):
        """按主键 id 删除单条（Core 级批量 DELETE，不触发 ORM 级联/事件）。"""
        session = cls._plugin_bundle().session()
        try:
            session.execute(sa_delete(cls).where(cls.id == rid))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @classmethod
    def truncate(cls):
        """清空本表全部记录（Core 级批量 DELETE，不触发 ORM 级联/事件）。"""
        session = cls._plugin_bundle().session()
        try:
            session.execute(sa_delete(cls))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def to_dict(self) -> dict:
        """转为 {列名: 值} 字典。"""
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}  # noqa


def build_plugin_base() -> Type[DeclarativeBase]:
    """为插件构建独立 MetaData + 自会话 ORM 的声明式 Base（无需传 id）。

    在插件模块顶层 ``PluginBase = build_plugin_base()``，模型继承 ``PluginBase`` 即可；
    再用 ``provides_models()`` 把模型类列表交给框架——框架据此（按插件实例类名自动判断
    plugin_id）建表/卸载，并把 plugin_id 绑定到该 MetaData，供模型 ORM 自解析会话。

    一插件应只调用一次 ``build_plugin_base()``、所有模型共享同一 Base/MetaData。

    :return: 一个新的、带独立 MetaData 与自会话 ORM 的 ``DeclarativeBase`` 子类。
    """
    plugin_metadata = MetaData()

    class PluginBase(PluginModelMixin, DeclarativeBase):
        # 覆盖默认 MetaData，使该 Base 下的模型与核心/其它插件隔离
        metadata = plugin_metadata

    return PluginBase


def _distinct_metadatas(models: List[Type]) -> List[MetaData]:
    """取模型列表中按对象去重、保序的 MetaData 集合（容错插件误用多个 Base）。"""
    seen: List[MetaData] = []
    for model in models:
        md = model.metadata
        if all(md is not existing for existing in seen):
            seen.append(md)
    return seen


def setup_plugin_database(plugin) -> None:
    """为声明了自管理模型的插件在其独立库中建表，并把 plugin_id 绑定到模型 MetaData。

    由 PluginManager 在启动/启用插件时调用。plugin_id 一律取 ``plugin.__class__.__name__``
    （唯一来源、无手传），故插件无需、也无从误传 id。仅当 ``provides_models()`` 非空才建表；
    声明了 ``provides_migration_location`` 的插件改走 Alembic 迁移链。

    对模型分属多个 MetaData（插件误用多个 Base）的情况逐个 attach + 建表，避免静默漏建。

    :param plugin: 插件实例，需实现 ``provides_models()``。
    """
    models = plugin.provides_models() or []
    location = None
    hook = getattr(plugin, "provides_migration_location", None)
    if hook:
        location = hook()
    plugin_id = plugin.__class__.__name__
    metadatas = _distinct_metadatas(models)

    # 声明了迁移目录 → 走 Alembic 迁移链（可选接入）；否则默认 create_tables
    if location:
        for md in metadatas:
            db_manager.attach_metadata(plugin_id, md)
        if not metadatas:
            db_manager.register_plugin(plugin_id)
        from app.db.plugin_migration import run_plugin_migrations
        run_plugin_migrations(plugin_id, location)
        return

    if not models:
        return
    # attach_metadata：注册容器 + 把 plugin_id 打到 MetaData.info（供模型 ORM 自解析会话），
    # 再经 create_tables 建表（SQLite 直接 create_all；PostgreSQL 先 CREATE SCHEMA 再建表）。
    for md in metadatas:
        db_manager.attach_metadata(plugin_id, md)
        db_manager.create_tables(plugin_id)


def teardown_plugin_database(plugin_id: str) -> None:
    """卸载插件时删除其独立库（释放容器并删除 .db 文件 / DROP SCHEMA）。

    由 PluginManager 在删除插件数据时调用；未注册时静默返回。drop 时会清除模型 MetaData 上的
    plugin_id 锚点，避免删库后再调用模型 ORM 静默重建空容器。
    """
    db_manager.drop_plugin(plugin_id)
