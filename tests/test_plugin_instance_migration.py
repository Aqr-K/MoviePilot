"""
插件配置搬迁与插件数据实例维度两个迁移的行为。

迁移只跑一次却要能重复执行：容器重启、迁移中断重来都会再次进入 upgrade，
不幂等就会重复插入或把已搬好的数据再搬一次。

降级方向另有一类风险：实例维度在旧结构里没有位置，硬回退就是把分身实例的配置与数据
悄悄抹掉。回退要么能还原，要么必须报错停下——不能一声不响地少数据。
"""
import importlib

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


TABLE_MIGRATION_MODULE = "database.versions.c7e1f9a4b8d2_3_1_0"
CONFIG_MIGRATION_MODULE = "database.versions.d1a5c8e3f7b2_3_1_1"
DATA_MIGRATION_MODULE = "database.versions.e5f2a9c7b3d1_3_1_2"


def _bind_migration(monkeypatch, connection, module_name: str):
    """把迁移脚本绑定到当前一次性连接。"""
    migration = importlib.import_module(module_name)
    context = MigrationContext.configure(connection)
    monkeypatch.setattr(migration, "op", Operations(context))
    return migration


def _config_schema() -> tuple[sa.MetaData, sa.Table, sa.Table]:
    """构造迁移涉及的系统配置表与插件实例配置表。"""
    metadata = sa.MetaData()
    systemconfig = sa.Table(
        "systemconfig",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String()),
        sa.Column("value", sa.JSON()),
    )
    pluginconfig = sa.Table(
        "pluginconfig",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.String(), nullable=False),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("log_level", sa.String()),
        sa.Column("log_expires_at", sa.DateTime()),
        sa.Column("config_data", sa.JSON()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("instance_id", "plugin_id", name="uk_instance_plugin"),
    )
    return metadata, systemconfig, pluginconfig


def _legacy_plugindata_schema() -> tuple[sa.MetaData, sa.Table]:
    """构造尚未带实例维度的插件数据表。"""
    metadata = sa.MetaData()
    plugindata = sa.Table(
        "plugindata",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.JSON()),
    )
    sa.Index("ix_plugindata_plugin_id_key", plugindata.c.plugin_id, plugindata.c.key)
    return metadata, plugindata


def _index_names(connection, table_name: str) -> set[str]:
    """返回表上全部索引名称。"""
    return {index["name"] for index in sa.inspect(connection).get_indexes(table_name)}


# --------------------------------------------------------------------------- #
# 系统配置 -> 插件实例配置
# --------------------------------------------------------------------------- #

def test_plugin_configs_move_to_plugin_config_table(monkeypatch):
    """
    plugin.<ID> 键整体搬到插件实例配置表，非插件键原样保留。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(systemconfig), [
            {"key": "plugin.AlphaPlugin", "value": {"enable": True, "cron": "0 0 * * *"}},
            {"key": "UserInstalledPlugins", "value": ["AlphaPlugin"]},
        ])
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()

        rows = connection.execute(sa.select(pluginconfig)).mappings().all()
        assert len(rows) == 1
        assert rows[0]["plugin_id"] == "AlphaPlugin"
        assert rows[0]["instance_id"] == "default"
        assert rows[0]["config_data"] == {"enable": True, "cron": "0 0 * * *"}
        assert rows[0]["is_enabled"] is True
        assert rows[0]["created_at"] is not None

        remaining = connection.execute(sa.select(systemconfig.c.key)).scalars().all()
        assert remaining == ["UserInstalledPlugins"]


@pytest.mark.parametrize("config, expected", [
    ({"enable": True}, True),
    ({"enable": False}, False),
    ({"enabled": True}, True),
    ({"enabled": False}, False),
    ({"enable": False, "enabled": True}, False),
    ({"cron": "0 0 * * *"}, False),
    ({}, False),
    (None, False),
])
def test_enabled_state_is_derived_from_both_spellings(monkeypatch, config, expected):
    """
    启用状态识别 enable 与 enabled 两种拼写，都没有时为未启用。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(systemconfig).values(key="plugin.AlphaPlugin", value=config)
        )
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()

        state = connection.execute(sa.select(pluginconfig.c.is_enabled)).scalar_one()
        assert state is expected


def test_config_migration_is_idempotent(monkeypatch):
    """
    重复执行不得重复插入，也不得覆盖搬迁后已改动的配置。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(systemconfig).values(key="plugin.AlphaPlugin", value={"enable": True})
        )
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()
        connection.execute(
            sa.update(pluginconfig).values(config_data={"enable": False, "changed": True})
        )
        connection.execute(
            sa.insert(systemconfig).values(key="plugin.AlphaPlugin", value={"enable": True})
        )
        migration.upgrade()

        rows = connection.execute(sa.select(pluginconfig)).mappings().all()
        assert len(rows) == 1
        assert rows[0]["config_data"] == {"enable": False, "changed": True}
        assert connection.execute(sa.select(systemconfig.c.key)).scalars().all() == []


def test_config_migration_skips_empty_plugin_id(monkeypatch):
    """
    只有前缀没有插件ID的键不构成一条实例配置，原样留在系统配置表。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(systemconfig).values(key="plugin.", value={"v": 1}))
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()

        assert connection.execute(sa.select(pluginconfig)).all() == []
        assert connection.execute(sa.select(systemconfig.c.key)).scalars().all() == ["plugin."]


def test_config_migration_downgrade_restores_system_config(monkeypatch):
    """
    回退把默认实例的配置写回系统配置表。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(systemconfig).values(key="plugin.AlphaPlugin", value={"enable": True})
        )
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()
        migration.downgrade()

        rows = connection.execute(
            sa.select(systemconfig.c.key, systemconfig.c.value)
        ).all()
        assert rows == [("plugin.AlphaPlugin", {"enable": True})]
        assert connection.execute(sa.select(pluginconfig)).all() == []


# --------------------------------------------------------------------------- #
# 插件数据实例维度
# --------------------------------------------------------------------------- #

def test_plugin_data_gets_instance_column_backfilled_to_default(monkeypatch):
    """
    加列之后老数据一律归入默认实例，不做任何归属推断。
    """
    engine = sa.create_engine("sqlite://")
    metadata, plugindata = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(plugindata), [
            {"plugin_id": "AlphaPlugin", "key": "k1", "value": {"v": 1}},
            {"plugin_id": "BetaPlugin", "key": "k2", "value": {"v": 2}},
        ])
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)

        migration.upgrade()

        instances = connection.execute(
            sa.text("SELECT instance_id FROM plugindata ORDER BY id")
        ).scalars().all()
        assert instances == ["default", "default"]


def test_plugin_data_index_gains_instance_dimension(monkeypatch):
    """
    定位索引扩到含实例维度，旧索引同时退役。
    """
    engine = sa.create_engine("sqlite://")
    metadata, _ = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)

        migration.upgrade()

        indexes = {
            index["name"]: tuple(index.get("column_names") or ())
            for index in sa.inspect(connection).get_indexes("plugindata")
        }
        assert indexes.get("ix_plugindata_plugin_instance_key") == (
            "plugin_id", "instance_id", "key",
        )
        assert "ix_plugindata_plugin_id_key" not in indexes


def test_plugin_data_migration_is_idempotent(monkeypatch):
    """
    重复执行不得因列或索引已存在而失败，也不得改写已有实例归属。
    """
    engine = sa.create_engine("sqlite://")
    metadata, plugindata = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(plugindata).values(plugin_id="AlphaPlugin", key="k1", value={"v": 1})
        )
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)

        migration.upgrade()
        connection.execute(
            sa.text("UPDATE plugindata SET instance_id = 'alpha' WHERE key = 'k1'")
        )
        migration.upgrade()

        instances = connection.execute(
            sa.text("SELECT instance_id FROM plugindata")
        ).scalars().all()
        assert instances == ["alpha"]
        assert "ix_plugindata_plugin_instance_key" in _index_names(connection, "plugindata")


def test_plugin_data_migration_downgrade_restores_legacy_shape(monkeypatch):
    """
    回退移除实例列并恢复按插件与键定位的索引。
    """
    engine = sa.create_engine("sqlite://")
    metadata, _ = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)

        migration.upgrade()
        migration.downgrade()

        columns = {
            column["name"] for column in sa.inspect(connection).get_columns("plugindata")
        }
        assert "instance_id" not in columns
        indexes = _index_names(connection, "plugindata")
        assert "ix_plugindata_plugin_id_key" in indexes
        assert "ix_plugindata_plugin_instance_key" not in indexes


# --------------------------------------------------------------------------- #
# 降级：分身实例无处安放时必须停下
# --------------------------------------------------------------------------- #

def test_config_downgrade_refuses_when_clone_instances_exist(monkeypatch):
    """
    分身实例的配置在旧结构里没有位置，回退必须报错，而不是把它们连表一起丢掉。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(pluginconfig), [
            {"instance_id": "default", "plugin_id": "AlphaPlugin",
             "is_enabled": True, "config_data": {"enable": True}},
            {"instance_id": "alpha", "plugin_id": "AlphaPlugin",
             "is_enabled": True, "config_data": {"enable": True, "token": "clone"}},
        ])
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        with pytest.raises(RuntimeError) as err:
            migration.downgrade()

        assert "alpha" in str(err.value)
        rows = connection.execute(sa.select(pluginconfig.c.instance_id)).scalars().all()
        assert sorted(rows) == ["alpha", "default"]


def test_config_downgrade_restores_enabled_state_missing_from_config(monkeypatch):
    """
    启用状态存在独立字段里，回退时要并回配置字典，否则实例回来就是禁用态。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(pluginconfig).values(
            instance_id="default", plugin_id="AlphaPlugin",
            is_enabled=True, config_data={"cron": "0 0 * * *"},
        ))
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.downgrade()

        value = connection.execute(sa.select(systemconfig.c.value)).scalar_one()
        assert migration._derive_enabled(value) is True
        assert value["cron"] == "0 0 * * *"


def test_config_downgrade_restores_disabled_state_contradicting_config(monkeypatch):
    """
    配置里写着启用、状态字段却是禁用时，以状态字段为准，回退不得把插件重新点亮。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(pluginconfig).values(
            instance_id="default", plugin_id="AlphaPlugin",
            is_enabled=False, config_data={"enable": True},
        ))
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.downgrade()

        value = connection.execute(sa.select(systemconfig.c.value)).scalar_one()
        assert migration._derive_enabled(value) is False


def test_config_downgrade_round_trips_the_enabled_state(monkeypatch):
    """
    升级再回退，插件的启用状态必须与出发时一致。
    """
    engine = sa.create_engine("sqlite://")
    metadata, systemconfig, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(systemconfig).values(key="plugin.AlphaPlugin", value={"enabled": True})
        )
        migration = _bind_migration(monkeypatch, connection, CONFIG_MIGRATION_MODULE)

        migration.upgrade()
        migration.downgrade()

        value = connection.execute(sa.select(systemconfig.c.value)).scalar_one()
        assert migration._derive_enabled(value) is True


def test_data_downgrade_refuses_when_clone_instance_rows_exist(monkeypatch):
    """
    删掉实例列会让分身的数据与默认实例挤在同一个 (plugin_id, key) 上，
    按键取数据从此返回任意一条——这种回退必须报错停下。
    """
    engine = sa.create_engine("sqlite://")
    metadata, plugindata = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(plugindata).values(plugin_id="AlphaPlugin", key="k1", value={"v": 1})
        )
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)
        migration.upgrade()
        connection.execute(sa.text(
            "INSERT INTO plugindata (plugin_id, key, value, instance_id) "
            "VALUES ('AlphaPlugin', 'k1', '{\"v\": 2}', 'alpha')"
        ))

        with pytest.raises(RuntimeError) as err:
            migration.downgrade()

        assert "alpha" in str(err.value)
        columns = {
            column["name"] for column in sa.inspect(connection).get_columns("plugindata")
        }
        assert "instance_id" in columns
        rows = connection.execute(
            sa.text("SELECT instance_id FROM plugindata ORDER BY instance_id")
        ).scalars().all()
        assert rows == ["alpha", "default"]


def test_data_downgrade_keeps_default_instance_rows(monkeypatch):
    """
    只有默认实例的数据时回退是无损的，行必须原样留在表里。
    """
    engine = sa.create_engine("sqlite://")
    metadata, plugindata = _legacy_plugindata_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(
            sa.insert(plugindata).values(plugin_id="AlphaPlugin", key="k1", value={"v": 1})
        )
        migration = _bind_migration(monkeypatch, connection, DATA_MIGRATION_MODULE)

        migration.upgrade()
        migration.downgrade()

        rows = connection.execute(
            sa.text("SELECT plugin_id, key FROM plugindata")
        ).all()
        assert rows == [("AlphaPlugin", "k1")]


def test_table_downgrade_refuses_to_drop_a_non_empty_config_table(monkeypatch):
    """
    删表是不可逆的，表里还有配置就必须报错，而不是静默 drop。
    """
    engine = sa.create_engine("sqlite://")
    metadata, _, pluginconfig = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        connection.execute(sa.insert(pluginconfig).values(
            instance_id="default", plugin_id="AlphaPlugin",
            is_enabled=True, config_data={"enable": True},
        ))
        migration = _bind_migration(monkeypatch, connection, TABLE_MIGRATION_MODULE)

        with pytest.raises(RuntimeError):
            migration.downgrade()

        assert "pluginconfig" in sa.inspect(connection).get_table_names()


def test_table_downgrade_drops_an_empty_config_table(monkeypatch):
    """
    表已清空时回退照常删表，完整降级链能一路走到底。
    """
    engine = sa.create_engine("sqlite://")
    metadata, _, _ = _config_schema()

    with engine.begin() as connection:
        metadata.create_all(connection)
        migration = _bind_migration(monkeypatch, connection, TABLE_MIGRATION_MODULE)

        migration.downgrade()

        assert "pluginconfig" not in sa.inspect(connection).get_table_names()
