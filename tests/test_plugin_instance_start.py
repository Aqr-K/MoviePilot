"""单独拉起插件实例：新实例进入运行态，同插件其余实例不被打断。"""
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.runtime.extensions.plugin_manager import PluginManager

PLUGIN_ID = "StartDemo"


class DemoPlugin:
    """插件类替身，记录每次实例化"""

    plugin_name = "示例插件"
    plugin_version = "1.0"
    auth_level = 1

    instantiations = []

    def __init__(self):
        """记录本次实例化"""
        self._plugin_id = None
        self._instance_id = None
        self.init_calls = []
        DemoPlugin.instantiations.append(self)

    def init_plugin(self, config=None):
        """生效配置"""
        self.init_calls.append(config)

    def get_state(self) -> bool:
        """运行状态"""
        return True


@pytest.fixture(autouse=True)
def clean_plugin_class():
    """清空插件类的实例化记录，隔离用例间的全局状态。"""
    DemoPlugin.instantiations = []
    yield
    DemoPlugin.instantiations = []


def make_manager(running=None) -> PluginManager:
    """
    构造与全局单例隔离、已加载 DemoPlugin 的插件管理器

    :param running: 预置的运行态实例表
    :return: 插件管理器
    """
    manager = object.__new__(PluginManager)
    manager._plugins = {PLUGIN_ID: DemoPlugin}
    manager._running_plugins = dict(running or {})
    for key in manager._running_plugins:
        manager._plugins[key] = DemoPlugin
    return manager


def start(manager: PluginManager, instance_id: str, config=None):
    """
    在打桩的配置与事件总线下拉起一个实例

    :param manager: 插件管理器
    :param instance_id: 实例ID
    :param config: 该实例的配置
    :return: (是否进入运行态, 扩展点注册替身)
    """
    config_oper = Mock()
    config_oper.get.return_value = config or {}
    with patch("app.runtime.extensions.plugin_manager.PluginConfigOper",
               return_value=config_oper), \
            patch("app.runtime.extensions.plugin_manager.eventmanager"), \
            patch("app.runtime.extensions.plugin_manager.set_and_check_auth_level",
                  return_value=True), \
            patch.object(PluginManager, "_register_plugin_extensions") as register, \
            patch("app.runtime.extensions.plugin_manager.clear_plugin_agent_tools_cache"):
        started = manager.start_instance(PLUGIN_ID, instance_id)
    return started, register


def test_starting_an_instance_brings_only_that_instance_up():
    """拉起分身只新增该实例，默认实例的运行对象原样保留。"""
    default_obj = Mock()
    manager = make_manager({PLUGIN_ID: default_obj})

    started, _ = start(manager, "alpha")

    assert started is True
    assert manager._running_plugins[PLUGIN_ID] is default_obj
    assert f"{PLUGIN_ID}@alpha" in manager._running_plugins


def test_starting_an_instance_does_not_reinstantiate_siblings():
    """拉起分身只构造一个新对象，兄弟实例不被重新实例化。"""
    manager = make_manager({PLUGIN_ID: Mock()})

    start(manager, "alpha")

    assert len(DemoPlugin.instantiations) == 1
    assert DemoPlugin.instantiations[0]._instance_id == "alpha"


def test_starting_an_instance_does_not_rescan_the_plugin_directory():
    """拉起分身不重扫插件目录，兄弟实例正在用的类对象不会被替换。"""
    manager = make_manager({PLUGIN_ID: Mock()})

    with patch("app.runtime.extensions.plugin_manager.load_selective_plugins") as loader:
        start(manager, "alpha")

    loader.assert_not_called()


def test_the_new_instance_gets_its_own_identity_and_config():
    """新实例拿到自己的身份与配置。"""
    manager = make_manager({PLUGIN_ID: Mock()})

    start(manager, "alpha", config={"key": "value"})

    created = manager._running_plugins[f"{PLUGIN_ID}@alpha"]
    assert created._plugin_id == PLUGIN_ID
    assert created._instance_id == "alpha"
    assert created.init_calls == [{"key": "value"}]


def test_extensions_are_registered_for_the_new_instance_only():
    """扩展点按新实例的实例键注册，不重扫同插件其余实例。"""
    manager = make_manager({PLUGIN_ID: Mock()})

    _, register = start(manager, "alpha")

    register.assert_called_once_with(f"{PLUGIN_ID}@alpha")


def test_starting_an_instance_of_an_unloaded_plugin_fails():
    """插件未加载时拉不起实例，且不污染运行态。"""
    manager = object.__new__(PluginManager)
    manager._plugins = {}
    manager._running_plugins = {}

    started, _ = start(manager, "alpha")

    assert started is False
    assert manager._running_plugins == {}


def test_starting_an_instance_rejects_an_illegal_instance_id():
    """实例标识非法时直接报错，不进入拉起流程。"""
    manager = make_manager({PLUGIN_ID: Mock()})

    with pytest.raises(ValueError):
        manager.start_instance(PLUGIN_ID, "bad id!")


def test_a_failing_instance_does_not_disturb_the_running_siblings():
    """新实例初始化抛错时兄弟实例照常运行。"""
    default_obj = Mock()
    manager = make_manager({PLUGIN_ID: default_obj})

    with patch.object(DemoPlugin, "init_plugin", side_effect=RuntimeError("boom")):
        started, _ = start(manager, "alpha")

    assert started is False
    assert manager._running_plugins[PLUGIN_ID] is default_obj


def test_create_instance_endpoint_does_not_reload_the_whole_plugin():
    """创建实例接口只拉起新实例，不再整插件重载。"""
    from app.api.endpoints import plugin as plugin_endpoint

    manager = MagicMock()
    manager.has_plugin.return_value = True
    manager.create_plugin_instance.return_value = f"{PLUGIN_ID}@alpha"
    manager.get_plugin_instances.return_value = [{
        "plugin_id": PLUGIN_ID,
        "instance_id": "alpha",
        "instance_key": f"{PLUGIN_ID}@alpha",
        "is_default": False,
        "running": True,
        "enabled": True,
    }]
    payload = Mock(instance_id="alpha", config={})

    with patch.object(plugin_endpoint, "PluginManager", return_value=manager), \
            patch.object(plugin_endpoint, "register_plugin"):
        response = plugin_endpoint.create_plugin_instance(PLUGIN_ID, payload, None)

    manager.reload_plugin.assert_not_called()
    manager.start_instance.assert_called_once_with(PLUGIN_ID, "alpha")
    assert response.success is True
    assert response.data["instance_key"] == f"{PLUGIN_ID}@alpha"


def enabled_plugin(state: bool) -> Mock:
    """
    构造指定启用状态的运行实例替身

    :param state: 启用状态
    :return: 插件实例替身
    """
    plugin = Mock()
    plugin.get_state.return_value = state
    return plugin


def test_plugin_state_is_true_when_any_instance_is_enabled():
    """传插件标识时任一运行实例启用即为在运行。"""
    manager = make_manager({PLUGIN_ID: enabled_plugin(False),
                            f"{PLUGIN_ID}@alpha": enabled_plugin(True)})

    assert manager.get_plugin_state(PLUGIN_ID) is True


def test_plugin_state_is_false_when_every_instance_is_disabled():
    """全部实例停用时插件不算在运行。"""
    manager = make_manager({PLUGIN_ID: enabled_plugin(False),
                            f"{PLUGIN_ID}@alpha": enabled_plugin(False)})

    assert manager.get_plugin_state(PLUGIN_ID) is False


def test_plugin_state_of_an_instance_key_is_judged_alone():
    """传实例键时只判定该实例，不受兄弟实例影响。"""
    manager = make_manager({PLUGIN_ID: enabled_plugin(True),
                            f"{PLUGIN_ID}@alpha": enabled_plugin(False)})

    assert manager.get_plugin_state(f"{PLUGIN_ID}@alpha") is False
    assert manager.get_plugin_state(PLUGIN_ID) is True


def test_plugin_state_survives_a_failing_probe():
    """单个实例取状态抛错按停用处理，其余实例照常判定。"""
    broken = Mock()
    broken.get_state.side_effect = RuntimeError("boom")
    manager = make_manager({PLUGIN_ID: broken, f"{PLUGIN_ID}@alpha": enabled_plugin(True)})

    assert manager.get_plugin_state(PLUGIN_ID) is True


def test_plugin_state_of_an_unloaded_plugin_is_false():
    """未加载的插件不算在运行。"""
    manager = make_manager({})

    assert manager.get_plugin_state(PLUGIN_ID) is False
