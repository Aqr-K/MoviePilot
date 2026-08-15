"""插件重置与实例删除对「实例身份」和「磁盘」的处置。

两处风险都不报错：重置按钮写的是清空配置与数据，真删掉实例定义就等于用户建的分身
凭空消失；删实例只清库不清盘，同名实例重建后会静默继承上一任的文件，而且这块盘再也
没有任何入口能回收。
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.api.endpoints.plugin import reset_plugin, reset_plugin_instance
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, PluginConfig
from app.db.models.plugindata import PluginData
from app.db.oper.pluginconfig import PluginConfigOper
from app.plugins import _PluginBase
from app.runtime.config import settings
from app.runtime.extensions.plugin_manager import PluginManager

PLUGIN_ID = "ResetDemoPlugin"


class ResetDemoPlugin(_PluginBase):
    """用于验证重置与实例回收的最小插件实现。"""

    plugin_name = "重置示例插件"

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
    """提供把插件登记为已加载的插件管理器，并隔离其运行态容器。"""
    manager = PluginManager()
    manager.plugins[PLUGIN_ID] = ResetDemoPlugin
    try:
        yield manager
    finally:
        manager.plugins.pop(PLUGIN_ID, None)
        manager.running_plugins.pop(PLUGIN_ID, None)
        manager.running_plugins.pop(f"{PLUGIN_ID}@alpha", None)


@pytest.fixture
def plugin_data_root(tmp_path, monkeypatch) -> Path:
    """把插件数据根目录指向用例私有的临时目录。"""
    root = tmp_path / "plugins"
    root.mkdir()
    monkeypatch.setattr(type(settings), "PLUGIN_DATA_PATH", property(lambda _self: root))
    return root


def instance_ids(plugin_id: str = PLUGIN_ID) -> list:
    """读出插件当前落库的实例标识，按标识排序便于断言。"""
    return sorted(record.instance_id for record in PluginConfigOper().list_instances(plugin_id))


# --------------------------------------------------------------------------- #
# 重置保留实例定义
# --------------------------------------------------------------------------- #

def test_reset_keeps_every_instance_definition(registered_manager):
    """重置清空配置与数据，用户建的分身实例本身必须还在。"""
    config_oper = PluginConfigOper()
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "default"}, DEFAULT_INSTANCE_ID)
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "alpha"}, "alpha")
    ResetDemoPlugin(instance_id="alpha").save_data("state", {"v": 1})

    assert registered_manager.reset_plugin(PLUGIN_ID) is True

    assert instance_ids() == ["alpha", DEFAULT_INSTANCE_ID]
    assert registered_manager.get_plugin_config(PLUGIN_ID, "alpha") == {}
    assert registered_manager.get_plugin_config(PLUGIN_ID, DEFAULT_INSTANCE_ID) == {}
    assert ResetDemoPlugin(instance_id="alpha").get_data("state") is None


def test_reset_of_single_instance_plugin_leaves_no_config_row(registered_manager):
    """只有默认实例的存量插件，重置后仍然一行配置都不留。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, DEFAULT_INSTANCE_ID)

    assert registered_manager.reset_plugin(PLUGIN_ID) is True

    assert instance_ids() == []
    assert registered_manager.get_plugin_config(PLUGIN_ID) == {}


def test_reset_does_not_invent_instances_for_a_plugin_without_config(registered_manager):
    """从没写过配置的插件，重置不得凭空造出一行实例配置。"""
    assert registered_manager.reset_plugin(PLUGIN_ID) is True

    assert instance_ids() == []


def test_reset_single_instance_only_touches_that_instance(registered_manager):
    """按实例重置只清这一个实例，同插件其余实例的配置与数据原样保留。"""
    config_oper = PluginConfigOper()
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "default"}, DEFAULT_INSTANCE_ID)
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "alpha"}, "alpha")
    ResetDemoPlugin().save_data("state", {"v": "default"})
    ResetDemoPlugin(instance_id="alpha").save_data("state", {"v": "alpha"})

    assert registered_manager.reset_plugin(PLUGIN_ID, "alpha") is True

    assert instance_ids() == ["alpha", DEFAULT_INSTANCE_ID]
    assert registered_manager.get_plugin_config(PLUGIN_ID, "alpha") == {}
    assert registered_manager.get_plugin_config(PLUGIN_ID, DEFAULT_INSTANCE_ID) == {
        "enable": True, "token": "default",
    }
    assert ResetDemoPlugin().get_data("state") == {"v": "default"}
    assert ResetDemoPlugin(instance_id="alpha").get_data("state") is None


def test_reset_single_instance_does_not_drop_the_shared_plugin_database(registered_manager):
    """自管理库由同插件全部实例共享，按实例重置不得把它拆掉。"""
    with patch("app.db.plugin.teardown_plugin_database") as teardown:
        registered_manager.reset_plugin(PLUGIN_ID, "alpha")

    teardown.assert_not_called()


def test_reset_whole_plugin_drops_the_shared_plugin_database(registered_manager):
    """整插件重置才拆除自管理库，与既有重置语义一致。"""
    with patch("app.db.plugin.teardown_plugin_database") as teardown:
        registered_manager.reset_plugin(PLUGIN_ID)

    teardown.assert_called_once_with(PLUGIN_ID)


def test_reset_rejects_illegal_instance_id(registered_manager):
    """实例标识非法时直接拒绝，不能落到按插件清空。"""
    with pytest.raises(ValueError):
        registered_manager.reset_plugin(PLUGIN_ID, "../etc")


# --------------------------------------------------------------------------- #
# 重置接口
# --------------------------------------------------------------------------- #

def test_reset_endpoint_no_longer_deletes_instance_definitions():
    """重置接口走保留实例定义的清空入口，不再按插件删光全部实例配置。"""
    plugin_manager = MagicMock()
    plugin_manager.reset_plugin.return_value = True

    with (
        patch("app.api.endpoints.plugin.PluginManager", return_value=plugin_manager),
        patch("app.api.endpoints.plugin.eventmanager"),
        patch("app.api.endpoints.plugin.reload_plugin"),
    ):
        result = reset_plugin(PLUGIN_ID, None)

    assert result.success is True
    plugin_manager.delete_plugin_config.assert_not_called()
    plugin_manager.reset_plugin.assert_called_once_with(PLUGIN_ID)


def test_reset_instance_endpoint_resets_only_that_instance():
    """按实例重置接口把实例标识透传到清空入口。"""
    plugin_manager = MagicMock()
    plugin_manager.get_plugin_instances.return_value = [
        {"instance_id": DEFAULT_INSTANCE_ID},
        {"instance_id": "alpha"},
    ]

    with (
        patch("app.api.endpoints.plugin.PluginManager", return_value=plugin_manager),
        patch("app.api.endpoints.plugin.eventmanager"),
        patch("app.api.endpoints.plugin.reload_plugin"),
        patch("app.api.endpoints.plugin.register_plugin"),
    ):
        result = reset_plugin_instance(PLUGIN_ID, "alpha")

    assert result.success is True
    plugin_manager.reset_plugin.assert_called_once_with(PLUGIN_ID, "alpha")


def test_reset_instance_endpoint_rejects_unknown_instance():
    """按实例重置一个不存在的实例应当拒绝，而不是静默清空。"""
    from fastapi import HTTPException

    plugin_manager = MagicMock()
    plugin_manager.get_plugin_instances.return_value = [{"instance_id": DEFAULT_INSTANCE_ID}]

    with (
        patch("app.api.endpoints.plugin.PluginManager", return_value=plugin_manager),
        patch("app.api.endpoints.plugin.eventmanager"),
    ):
        with pytest.raises(HTTPException) as err:
            reset_plugin_instance(PLUGIN_ID, "ghost")

    assert err.value.status_code == 404
    plugin_manager.reset_plugin.assert_not_called()


# --------------------------------------------------------------------------- #
# 删实例回收数据目录
# --------------------------------------------------------------------------- #

def test_deleting_an_instance_reclaims_its_data_directory(
        registered_manager, plugin_data_root
):
    """删实例要把它独占的数据目录一并回收，否则同名实例重建会继承旧文件。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")
    data_path = ResetDemoPlugin(instance_id="alpha").get_data_path()
    (data_path / "cache.bin").write_bytes(b"stale")

    registered_manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert not data_path.exists()


def test_deleting_an_instance_keeps_the_default_instance_directory(
        registered_manager, plugin_data_root
):
    """默认实例的数据目录就是插件目录本身，删分身绝不能连它一起端掉。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")
    default_path = ResetDemoPlugin().get_data_path()
    (default_path / "keep.bin").write_bytes(b"keep")
    ResetDemoPlugin(instance_id="alpha").get_data_path()

    registered_manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert default_path.exists()
    assert (default_path / "keep.bin").read_bytes() == b"keep"


def test_deleting_an_instance_keeps_sibling_instance_directories(
        registered_manager, plugin_data_root
):
    """回收范围止于被删实例，同插件其它分身的目录不受影响。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "beta")
    alpha_path = ResetDemoPlugin(instance_id="alpha").get_data_path()
    beta_path = ResetDemoPlugin(instance_id="beta").get_data_path()
    (beta_path / "keep.bin").write_bytes(b"keep")

    registered_manager.delete_plugin_instance(PLUGIN_ID, "beta")

    assert alpha_path.exists()
    assert not beta_path.exists()


def test_deleting_an_instance_without_data_directory_is_not_an_error(
        registered_manager, plugin_data_root
):
    """实例从未落过盘时删除照常完成。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")

    removed = registered_manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert removed == f"{PLUGIN_ID}@alpha"


def test_recreated_instance_does_not_inherit_the_previous_files(
        registered_manager, plugin_data_root
):
    """同名实例重建后拿到的是空目录，不继承上一任留下的素材。"""
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")
    (ResetDemoPlugin(instance_id="alpha").get_data_path() / "cache.bin").write_bytes(b"stale")
    registered_manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    rebuilt = ResetDemoPlugin(instance_id="alpha").get_data_path()

    assert rebuilt.exists()
    assert list(rebuilt.iterdir()) == []
