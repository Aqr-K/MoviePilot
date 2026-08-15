"""
插件声明式基类的构建。

每个插件经 ``build_plugin_base`` 取得一个拥有独立 MetaData 的声明式 Base，
其模型继承该 Base 即与核心库及其它插件互不可见——建表、删表、迁移都不会互相牵连。
"""
from typing import Type

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

from app.db.plugin.registry import db_manager


def build_plugin_base(plugin_id: str) -> Type[DeclarativeBase]:
    """
    为插件构建独立 MetaData 的声明式 Base，并登记到其数据库容器
    :param plugin_id: 插件唯一标识，同时决定其独立库路径与 schema 名
    :return: 插件模型应继承的 DeclarativeBase 子类
    """
    bundle = db_manager.register_plugin(plugin_id)
    plugin_metadata = MetaData()

    class PluginBase(DeclarativeBase):
        # 覆盖默认 MetaData，使该 Base 下的模型与核心及其它插件隔离
        metadata = plugin_metadata

    # 让 create_tables 能定位到该插件需要创建的表集合
    bundle.metadata = plugin_metadata
    return PluginBase
