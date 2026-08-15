"""插件列表的实例视图：每个插件带出其全部实例，运行状态按实例汇总。"""
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.runtime.extensions.plugin_manager import PluginManager


class DemoPlugin:
    """插件类替身，只提供列表渲染需要的属性"""

    plugin_name = "示例插件"
    plugin_desc = "用于列表渲染"
    plugin_version = "1.0"
    plugin_order = 1
    auth_level = 1

    def get_page(self):
        """详情页面"""
        return []


def make_record(plugin_id: str, instance_id: str, is_enabled: bool) -> SimpleNamespace:
    """
    构造一条实例配置记录替身

    :param plugin_id: 插件ID
    :param instance_id: 实例ID
    :param is_enabled: 是否启用
    :return: 配置记录替身
    """
    return SimpleNamespace(plugin_id=plugin_id, instance_id=instance_id, is_enabled=is_enabled)


def make_running(enabled: bool) -> Mock:
    """
    构造运行态插件实例替身

    :param enabled: 实例启用状态
    :return: 插件实例替身
    """
    plugin = Mock()
    plugin.get_state.return_value = enabled
    return plugin


def make_manager(plugins: dict, running: dict) -> PluginManager:
    """
    构造与全局单例隔离的插件管理器

    :param plugins: 插件表 {实例键: 插件类}
    :param running: 运行态插件表 {实例键: 插件实例}
    :return: 插件管理器
    """
    manager = object.__new__(PluginManager)
    manager._plugins = plugins
    manager._running_plugins = running
    return manager


def local_plugins(manager: PluginManager, records: dict, installed=("Demo",)):
    """
    在给定的实例配置与已安装清单下取插件列表

    :param manager: 插件管理器
    :param records: {插件ID: [配置记录]}
    :param installed: 已安装的插件ID
    :return: 插件列表
    """
    config_oper = Mock()
    config_oper.list_all_instances.return_value = records
    system_oper = Mock()
    system_oper.get.return_value = list(installed)
    with patch("app.runtime.extensions.plugin_manager.PluginConfigOper", return_value=config_oper), \
            patch("app.runtime.extensions.plugin_manager.SystemConfigOper", return_value=system_oper), \
            patch("app.runtime.extensions.plugin_manager.set_and_check_auth_level", return_value=True):
        return manager.get_local_plugins()


def test_single_instance_plugin_reports_one_default_instance():
    """单实例插件带出一个默认实例，实例键即插件标识。"""
    manager = make_manager({"Demo": DemoPlugin}, {"Demo": make_running(True)})

    plugins = local_plugins(manager, {})

    assert len(plugins) == 1
    assert [instance.model_dump() for instance in plugins[0].instances] == [{
        "plugin_id": "Demo",
        "instance_id": DEFAULT_INSTANCE_ID,
        "instance_key": "Demo",
        "is_default": True,
        "running": True,
        "enabled": True,
    }]


def test_clone_instances_are_listed_under_their_plugin():
    """分身实例挂在所属插件那一行下，而不是各自单独成行。"""
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin},
        {"Demo": make_running(True), "Demo@alpha": make_running(False)},
    )
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, True),
                        make_record("Demo", "alpha", False)]}

    plugins = local_plugins(manager, records)

    assert len(plugins) == 1
    assert [(instance.instance_id, instance.instance_key, instance.enabled)
            for instance in plugins[0].instances] == [
        (DEFAULT_INSTANCE_ID, "Demo", True),
        ("alpha", "Demo@alpha", False),
    ]


def test_plugin_state_is_true_when_any_instance_is_enabled():
    """默认实例停用但分身启用时，插件整体仍算在运行。"""
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin},
        {"Demo": make_running(False), "Demo@alpha": make_running(True)},
    )
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, False),
                        make_record("Demo", "alpha", True)]}

    plugins = local_plugins(manager, records)

    assert plugins[0].state is True


def test_plugin_state_is_false_when_every_instance_is_disabled():
    """全部实例都停用时插件整体不算在运行。"""
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin},
        {"Demo": make_running(False), "Demo@alpha": make_running(False)},
    )
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, False),
                        make_record("Demo", "alpha", False)]}

    plugins = local_plugins(manager, records)

    assert plugins[0].state is False


def test_instance_not_running_falls_back_to_its_stored_state():
    """未进入运行态的实例按落库的启用状态呈现。"""
    manager = make_manager({"Demo": DemoPlugin, "Demo@alpha": DemoPlugin},
                           {"Demo": make_running(True)})
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, True),
                        make_record("Demo", "alpha", True)]}

    plugins = local_plugins(manager, records)

    clone = plugins[0].instances[1]
    assert clone.instance_id == "alpha"
    assert clone.running is False
    assert clone.enabled is True


def test_plugin_enabled_in_config_but_not_loaded_is_not_running():
    """配置里启用却没能加载起来的插件不算在运行，避免把加载失败显示成正常。"""
    manager = make_manager({"Demo": DemoPlugin}, {})
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, True)]}

    plugins = local_plugins(manager, records)

    assert plugins[0].instances[0].enabled is True
    assert plugins[0].instances[0].running is False
    assert plugins[0].state is False


def test_instance_view_survives_a_failing_state_probe():
    """单个实例取状态抛错时按停用呈现，不影响同插件其余实例。"""
    broken = Mock()
    broken.get_state.side_effect = RuntimeError("boom")
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin},
        {"Demo": broken, "Demo@alpha": make_running(True)},
    )
    records = {"Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, True),
                        make_record("Demo", "alpha", True)]}

    plugins = local_plugins(manager, records)

    assert [instance.enabled for instance in plugins[0].instances] == [False, True]
    assert plugins[0].state is True


def test_the_list_reads_instance_configs_in_one_query():
    """列表整体只查一次实例配置，不随插件数量放大查询次数。"""
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin, "Other": DemoPlugin},
        {},
    )
    config_oper = Mock()
    config_oper.list_all_instances.return_value = {}
    system_oper = Mock()
    system_oper.get.return_value = ["Demo", "Other"]
    with patch("app.runtime.extensions.plugin_manager.PluginConfigOper", return_value=config_oper), \
            patch("app.runtime.extensions.plugin_manager.SystemConfigOper", return_value=system_oper), \
            patch("app.runtime.extensions.plugin_manager.set_and_check_auth_level", return_value=True):
        manager.get_local_plugins()

    assert config_oper.list_all_instances.call_count == 1
    assert config_oper.list_instances.call_count == 0


def test_the_list_still_renders_when_instance_configs_are_unreadable():
    """实例配置读取失败时列表照常返回，各插件退化为默认实例。"""
    manager = make_manager({"Demo": DemoPlugin}, {"Demo": make_running(True)})
    config_oper = Mock()
    config_oper.list_all_instances.side_effect = RuntimeError("db down")
    system_oper = Mock()
    system_oper.get.return_value = ["Demo"]
    with patch("app.runtime.extensions.plugin_manager.PluginConfigOper", return_value=config_oper), \
            patch("app.runtime.extensions.plugin_manager.SystemConfigOper", return_value=system_oper), \
            patch("app.runtime.extensions.plugin_manager.set_and_check_auth_level", return_value=True):
        plugins = manager.get_local_plugins()

    assert [instance.instance_id for instance in plugins[0].instances] == [DEFAULT_INSTANCE_ID]


def test_instances_of_different_plugins_do_not_mix():
    """不同插件的实例各归各行。"""
    manager = make_manager(
        {"Demo": DemoPlugin, "Demo@alpha": DemoPlugin, "Other": DemoPlugin},
        {},
    )
    records = {
        "Demo": [make_record("Demo", DEFAULT_INSTANCE_ID, True),
                 make_record("Demo", "alpha", True)],
        "Other": [make_record("Other", DEFAULT_INSTANCE_ID, False)],
    }

    plugins = local_plugins(manager, records, installed=("Demo", "Other"))

    by_id = {plugin.id: plugin for plugin in plugins}
    assert [instance.instance_key for instance in by_id["Demo"].instances] == ["Demo", "Demo@alpha"]
    assert [instance.instance_key for instance in by_id["Other"].instances] == ["Other"]
