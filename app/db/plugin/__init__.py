"""
插件自管理数据库。

为「插件自建表、自维护、自会话管理」提供框架支持，与核心库完全解耦：插件表挂在
各自独立的 MetaData 上，落到插件专属的库文件或 schema，核心的建表与迁移看不见
它们，反之亦然。职责分布在：

- container    单个插件的数据库容器
- registry     按插件 ID 管理容器生命周期的注册表
- declarative  独立 MetaData 的插件声明式基类
- lifecycle    插件启用与删除时的建表、拆除
- migration    per-plugin Alembic env 与迁移运行器
"""
from app.db.plugin.container import PluginDatabase
from app.db.plugin.declarative import build_plugin_base
from app.db.plugin.lifecycle import setup_plugin_database, teardown_plugin_database
from app.db.plugin.registry import db_manager

__all__ = [
    "PluginDatabase",
    "build_plugin_base",
    "db_manager",
    "setup_plugin_database",
    "teardown_plugin_database",
]
