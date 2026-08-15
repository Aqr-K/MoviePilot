"""
插件实例身份，以及配置、数据与数据目录按实例寻址的行为。

这一组的风险全部指向「串到同一份存储」：身份回退取错、寻址少带一维，
表现都是两个实例读写同一行数据，不抛异常也查不出来。
"""
import asyncio
from datetime import datetime, timedelta

import pytest

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, PluginConfig
from app.db.models.plugindata import PluginData
from app.db.oper.pluginconfig import PluginConfigOper, derive_enabled, resolve_log_level
from app.db.oper.systemconfig import SystemConfigOper
from app.plugins import _PluginBase
from app.runtime.config import settings
from app.runtime.extensions.plugin_manager import PluginManager


class DemoPlugin(_PluginBase):
    """用于验证身份寻址的最小插件实现。"""

    plugin_name = "示例插件"

    def init_plugin(self, config: dict = None):
        pass

    def get_state(self) -> bool:
        return True

    def get_api(self):
        return []

    def get_form(self):
        return [], {}

    def get_page(self):
        return None

    def stop_service(self):
        pass


@pytest.fixture(autouse=True)
def _track(db):
    """把本文件涉及的表纳入用例级回收。"""
    db.watermark(PluginConfig, PluginData)


@pytest.fixture
def registered_manager():
    """提供把 DemoPlugin 登记为已加载插件的插件管理器。"""
    manager = PluginManager()
    manager.plugins["DemoPlugin"] = DemoPlugin
    try:
        yield manager
    finally:
        manager.plugins.pop("DemoPlugin", None)


# --------------------------------------------------------------------------- #
# 实例身份
# --------------------------------------------------------------------------- #

def test_identity_defaults_to_class_name_and_default_instance():
    """
    未注入身份时，插件标识取类名、实例标识取默认实例——官方插件依赖这一缺省。
    """
    plugin = DemoPlugin()

    assert plugin.plugin_id == "DemoPlugin"
    assert plugin.instance_id == DEFAULT_INSTANCE_ID


def test_identity_can_be_injected_at_construction():
    """
    身份可在构造时注入，分身无需靠改类名换取独立存储。
    """
    plugin = DemoPlugin(plugin_id="OriginPlugin", instance_id="alpha")

    assert plugin.plugin_id == "OriginPlugin"
    assert plugin.instance_id == "alpha"


def test_blank_instance_id_falls_back_to_default_instance():
    """
    空实例标识等同于未指定，回落到默认实例而不是造出一个空实例。
    """
    assert DemoPlugin(instance_id=None).instance_id == DEFAULT_INSTANCE_ID
    assert DemoPlugin(instance_id="").instance_id == DEFAULT_INSTANCE_ID


@pytest.mark.parametrize("instance_id", ["../evil", "a/b", "..", "with space", "x" * 65])
def test_illegal_instance_id_is_rejected(instance_id):
    """
    实例标识会拼进数据目录，含分隔符或点号时必须当场拒绝而不是拼出目录树之外的路径。
    """
    with pytest.raises(ValueError):
        DemoPlugin(instance_id=instance_id)


# --------------------------------------------------------------------------- #
# 配置存储
# --------------------------------------------------------------------------- #

def test_update_config_writes_plugin_config_table_not_system_config(db):
    """
    插件配置落在插件实例配置表，系统配置表不再承载 plugin.<ID> 键。
    """
    plugin = DemoPlugin()

    plugin.update_config({"enable": True, "cron": "0 0 * * *"})

    record = PluginConfig.get_instance(db.session, "DemoPlugin", DEFAULT_INSTANCE_ID)
    assert record is not None
    assert record.config_data == {"enable": True, "cron": "0 0 * * *"}
    assert record.is_enabled is True
    assert SystemConfigOper().get("plugin.DemoPlugin") is None


def test_get_config_reads_back_written_config():
    """
    插件自读必须拿回自己写入的配置。
    """
    plugin = DemoPlugin()
    plugin.update_config({"enable": False, "token": "abc"})

    assert plugin.get_config() == {"enable": False, "token": "abc"}


def test_config_is_isolated_between_instances():
    """
    同一插件的两个实例各持一份配置，互不覆盖。
    """
    default_instance = DemoPlugin()
    alpha = DemoPlugin(instance_id="alpha")

    default_instance.update_config({"token": "default-token"})
    alpha.update_config({"token": "alpha-token"})

    assert default_instance.get_config() == {"token": "default-token"}
    assert alpha.get_config() == {"token": "alpha-token"}


def test_explicit_plugin_id_overrides_identity_fallback():
    """
    显式传入插件ID时优先于实例身份，跨插件读写配置的既有语义保持不变。
    """
    plugin = DemoPlugin()
    plugin.update_config({"v": 1}, plugin_id="OtherPlugin")

    assert plugin.get_config(plugin_id="OtherPlugin") == {"v": 1}
    assert plugin.get_config() is None


def test_plugin_and_manager_read_the_same_config(registered_manager):
    """
    插件自读与管理器读取必须落在同一行，否则保存后界面与运行态会分叉。
    """
    plugin = DemoPlugin()
    plugin.update_config({"enable": True, "interval": 30})

    assert registered_manager.get_plugin_config("DemoPlugin") == {
        "enable": True, "interval": 30
    }

    registered_manager.save_plugin_config("DemoPlugin", {"enable": False, "interval": 60})

    assert plugin.get_config() == {"enable": False, "interval": 60}


def test_manager_async_save_is_visible_to_plugin(registered_manager):
    """
    异步保存与同步读取共用一张表，写入立即可见。
    """
    plugin = DemoPlugin()

    asyncio.run(registered_manager.async_save_plugin_config("DemoPlugin", {"enabled": True}))

    assert plugin.get_config() == {"enabled": True}
    record = PluginConfigOper().get_instance("DemoPlugin")
    assert record.is_enabled is True


def test_manager_delete_config_clears_all_instances(registered_manager):
    """
    删除插件配置需要连同分身实例一并清除，避免残留配置在重装后复活。
    """
    DemoPlugin().update_config({"v": 1})
    DemoPlugin(instance_id="alpha").update_config({"v": 2})

    assert registered_manager.delete_plugin_config("DemoPlugin", force=True) is True

    assert PluginConfigOper().list_instances("DemoPlugin") == []


# --------------------------------------------------------------------------- #
# 启用状态与日志等级
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("config, expected", [
    ({"enable": True}, True),
    ({"enable": False}, False),
    ({"enabled": True}, True),
    ({"enabled": False}, False),
    ({"enable": False, "enabled": True}, False),
    ({"other": 1}, False),
    ({}, False),
    (None, False),
])
def test_derive_enabled_recognizes_both_spellings(config, expected):
    """
    enable 与 enabled 两种拼写都要认，都没有时视为未启用。
    """
    assert derive_enabled(config) is expected


def test_resolve_log_level_falls_back_to_global():
    """
    实例日志等级为空、非法或已过期时回落到全局等级。
    """
    now = datetime(2026, 8, 15, 12, 0, 0)

    assert resolve_log_level(None, None, "INFO", now) == "INFO"
    assert resolve_log_level("TRACE", None, "INFO", now) == "INFO"
    assert resolve_log_level("DEBUG", None, "INFO", now) == "DEBUG"
    assert resolve_log_level("DEBUG", now + timedelta(minutes=1), "INFO", now) == "DEBUG"
    assert resolve_log_level("DEBUG", now - timedelta(seconds=1), "INFO", now) == "INFO"


def test_log_level_round_trips_and_expires():
    """
    日志等级可读写，过期之后取到的是全局等级。
    """
    oper = PluginConfigOper()
    now = datetime(2026, 8, 15, 12, 0, 0)
    oper.set_log_level("DemoPlugin", "DEBUG", expires_at=now + timedelta(hours=1))

    assert oper.get_log_level("DemoPlugin", "INFO", now=now) == "DEBUG"
    assert oper.get_log_level("DemoPlugin", "INFO", now=now + timedelta(hours=2)) == "INFO"


def test_saving_config_keeps_log_level():
    """
    保存业务配置不得抹掉实例的日志等级设置。
    """
    oper = PluginConfigOper()
    oper.set_log_level("DemoPlugin", "ERROR")

    DemoPlugin().update_config({"enable": True})

    assert oper.get_instance("DemoPlugin").log_level == "ERROR"


# --------------------------------------------------------------------------- #
# 插件数据
# --------------------------------------------------------------------------- #

def test_plugin_data_is_isolated_between_instances():
    """
    两个实例各写各的数据，读取不得串到对方那一行。
    """
    default_instance = DemoPlugin()
    alpha = DemoPlugin(instance_id="alpha")

    default_instance.save_data("state", {"v": "default"})
    alpha.save_data("state", {"v": "alpha"})

    assert default_instance.get_data("state") == {"v": "default"}
    assert alpha.get_data("state") == {"v": "alpha"}


def test_plugin_data_delete_only_touches_own_instance():
    """
    删除自己的数据不得波及同插件的其他实例。
    """
    default_instance = DemoPlugin()
    alpha = DemoPlugin(instance_id="alpha")
    default_instance.save_data("state", {"v": "default"})
    alpha.save_data("state", {"v": "alpha"})

    default_instance.del_data("state")

    assert default_instance.get_data("state") is None
    assert alpha.get_data("state") == {"v": "alpha"}


def test_plugin_data_listing_is_scoped_to_instance():
    """
    不带键读取只返回本实例的数据。
    """
    default_instance = DemoPlugin()
    alpha = DemoPlugin(instance_id="alpha")
    default_instance.save_data("k1", 1)
    alpha.save_data("k2", 2)

    assert {row.key for row in default_instance.get_data()} == {"k1"}
    assert {row.key for row in alpha.get_data()} == {"k2"}


def test_async_plugin_data_is_isolated_between_instances():
    """
    异步读写同样按实例隔离。
    """
    default_instance = DemoPlugin()
    alpha = DemoPlugin(instance_id="alpha")

    asyncio.run(default_instance.async_save_data("state", {"v": "default"}))
    asyncio.run(alpha.async_save_data("state", {"v": "alpha"}))

    assert asyncio.run(default_instance.async_get_data("state")) == {"v": "default"}
    assert asyncio.run(alpha.async_get_data("state")) == {"v": "alpha"}


def test_legacy_rows_without_instance_belong_to_default_instance(db):
    """
    未带实例标识写入的老数据归属默认实例，升级后默认实例仍能读到。
    """
    db.add(PluginData(plugin_id="DemoPlugin", key="legacy", value={"v": 1}))

    assert DemoPlugin().get_data("legacy") == {"v": 1}
    assert DemoPlugin(instance_id="alpha").get_data("legacy") is None


def test_manager_delete_plugin_data_clears_all_instances(registered_manager):
    """
    删除插件数据是整插件级操作，分身数据一并清除。
    """
    DemoPlugin().save_data("state", 1)
    DemoPlugin(instance_id="alpha").save_data("state", 2)

    assert registered_manager.delete_plugin_data("DemoPlugin", force=True) is True

    assert DemoPlugin().get_data("state") is None
    assert DemoPlugin(instance_id="alpha").get_data("state") is None


# --------------------------------------------------------------------------- #
# 数据目录与消息跳转
# --------------------------------------------------------------------------- #

def test_default_instance_data_path_is_unchanged():
    """
    默认实例的数据目录必须保持升级前的位置，否则存量插件的文件全部失联。
    """
    assert DemoPlugin().get_data_path() == settings.PLUGIN_DATA_PATH / "DemoPlugin"


def test_non_default_instance_data_path_is_nested_under_plugin():
    """
    非默认实例在插件目录下按实例分隔，且不与插件自管理库文件同名。
    """
    path = DemoPlugin(instance_id="alpha").get_data_path()

    assert path == settings.PLUGIN_DATA_PATH / "DemoPlugin" / "instances" / "alpha"
    assert path.exists()
    assert path != settings.PLUGIN_DATA_PATH / "DemoPlugin" / "DemoPlugin.db"


def test_post_message_link_uses_instance_plugin_id(monkeypatch):
    """
    消息跳转链接指向实例身份持有的插件ID。
    """
    monkeypatch.setattr(settings, "APP_DOMAIN", "https://mp.example.com")
    plugin = DemoPlugin(plugin_id="OriginPlugin")
    captured = []
    plugin.chain = type("_Chain", (), {"post_message": lambda _self, message: captured.append(message)})()

    plugin.post_message(title="标题")

    assert captured[0].link.endswith("#/plugins?tab=installed&id=OriginPlugin")
