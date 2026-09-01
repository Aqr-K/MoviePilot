"""DbDemo 参考插件回归——验证「插件自管理数据库」端到端可用。

DbDemo 是插件自管理 DB 框架的最小参考实现：声明 provides_models() → 框架建独立库，
插件用 self.get_plugin_db().session() 自会话读写。本测试覆盖：模型声明、经 setup 建表、
CRUD、与核心库物理隔离、teardown 删库。绕过 _PluginBase 重型 __init__（仅验证 DB 行为）。
"""
import pytest

# app/plugins/** 被 .gitignore 忽略：参考插件 dbdemo 作为磁盘开发件存在（同 githubsso 约定）。
# 纯净检出（无任何插件）时优雅跳过本文件，框架本身的接线测试见 test_plugin_db_wiring.py。
pytest.importorskip("app.plugins.dbdemo")


def _new_plugin():
    """构造 DbDemo 实例但绕过 _PluginBase.__init__（其会实例化多个 Oper/单例）。"""
    from app.plugins.dbdemo import DbDemo
    return DbDemo.__new__(DbDemo)


def test_dbdemo_declares_self_managed_model():
    """provides_models() 应声明 DbDemoNote（框架据此建独立表）。"""
    from app.plugins.dbdemo import DbDemoNote

    models = _new_plugin().provides_models()
    assert DbDemoNote in models


def test_dbdemo_self_managed_crud_and_isolation():
    """经 setup 在独立库建表 → 插件自会话 CRUD → 与核心库物理隔离 → teardown 删库。"""
    from sqlalchemy import inspect

    from app.db import Base as CoreBase
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager
    from app.db.plugin import setup_plugin_database, teardown_plugin_database

    plugin = _new_plugin()
    db_path = None
    try:
        # 框架按 provides_models 在插件独立库建表
        setup_plugin_database(plugin)
        bundle = db_manager.get("DbDemo")
        db_path = bundle.db_path
        # 显式传 schema：SQLite 下 bundle.schema 为 None（默认 schema），PG 下 Inspector 反射
        # 不走 schema_translate_map，须显式传 plugin_<id> schema 才能查到表
        assert "dbdemo_note" in inspect(bundle.engine).get_table_names(schema=bundle.schema)

        # 插件自会话写入 + 读取
        note_id = plugin.add_note("hello world")
        assert isinstance(note_id, int) and note_id > 0
        notes = plugin.list_notes()
        assert [n["content"] for n in notes] == ["hello world"]
        assert notes[0]["created_at"]  # created_at 字段映射非空

        # 删除不存在的 id 返回 False（覆盖 get is None 分支）；删除存在的返回 True
        assert plugin.delete_note(999999) is False
        assert plugin.delete_note(note_id) is True
        assert plugin.list_notes() == []

        # 物理隔离：插件表既不在核心 MetaData，也不在核心 user.db
        assert "dbdemo_note" not in CoreBase.metadata.tables
        assert "dbdemo_note" not in inspect(CoreEngine).get_table_names()
    finally:
        teardown_plugin_database("DbDemo")
    # teardown 删除独立 .db 文件
    assert db_path is not None and not db_path.exists()
    assert db_manager.get("DbDemo") is None


def test_dbdemo_get_plugin_db_registers_isolated_container():
    """get_plugin_db() 按类名注册独立容器，指向 plugins/DbDemo/DbDemo.db。"""
    from app.core.config import settings
    from app.db import Engine as CoreEngine
    from app.db.manager import db_manager

    plugin = _new_plugin()
    try:
        bundle = plugin.get_plugin_db()
        assert bundle.plugin_id == "DbDemo"
        expected = settings.PLUGIN_DATA_PATH / "DbDemo" / "DbDemo.db"
        assert str(expected) in str(bundle.engine.url)
        assert bundle.engine is not CoreEngine
    finally:
        db_manager.dispose("DbDemo")
