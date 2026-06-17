"""
S9c 回归：PluginManager 的 12 个只读元数据聚合访问器抽至 app.helper.plugin_metadata。

这些访问器对 PluginManager 实例状态的唯一耦合是 _running_plugins 一个字典，故抽成
模块级函数（首参 running_plugins），PluginManager 保留一行委托门面 → api/agent/command/
scheduler/chain 等大量调用方 PluginManager().get_plugin_xxx() 零改动。

函数体逐字迁出（仅 self._running_plugins → running_plugins，dict() 快照语义不变），
可用 fake 插件直接做**行为单测**证明等价。
"""
import inspect

from app.helper import plugin_metadata
from app.helper.plugin_manager import PluginManager

NAMES = [
    "get_plugin_commands", "get_plugin_apis", "get_plugin_services", "get_plugin_modules",
    "get_plugin_actions", "get_plugin_agent_tools", "get_plugin_remote_entry", "get_plugin_remotes",
    "get_plugin_auth_providers", "get_plugin_sidebar_nav", "get_plugin_dashboard_meta", "get_plugin_dashboard",
]


class _FakePlugin:
    def get_state(self):
        return True

    def get_command(self):
        return [{"cmd": "/x", "desc": "d"}]

    def get_service(self):
        return [{"id": "s1", "name": "svc"}]

    def get_api(self):
        return [{"path": "/ping", "endpoint": None, "methods": ["GET"]}]


class _DisabledPlugin:
    def get_state(self):
        return False

    def get_command(self):
        return [{"cmd": "/y"}]


# ---- (a) 结构契约：12 门面委托、12 函数就位 ----

def test_facades_and_functions_present():
    for n in NAMES:
        assert hasattr(PluginManager, n), f"PluginManager 缺门面 {n}"
        assert hasattr(plugin_metadata, n), f"plugin_metadata 缺函数 {n}"


def test_facade_delegates_to_module():
    src = inspect.getsource(PluginManager.get_plugin_commands)
    assert "plugin_metadata.get_plugin_commands(self._running_plugins" in src


# ---- (b) 行为单测：聚合 / pid 注入 / get_state 过滤 / pid 过滤 ----

def test_get_plugin_commands_aggregates_and_injects_pid():
    rp = {"FakeP": _FakePlugin()}
    assert plugin_metadata.get_plugin_commands(rp, None) == [{"cmd": "/x", "desc": "d", "pid": "FakeP"}]


def test_get_plugin_services_aggregates():
    rp = {"FakeP": _FakePlugin()}
    assert plugin_metadata.get_plugin_services(rp, None) == [{"id": "s1", "name": "svc"}]


def test_get_plugin_apis_prefixes_path():
    rp = {"FakeP": _FakePlugin()}
    apis = plugin_metadata.get_plugin_apis(rp, None)
    assert apis[0]["path"] == "/FakeP/ping"          # 路径加插件前缀
    assert apis[0]["auth"] == "apikey"                # 默认 auth


def test_disabled_plugin_skipped_and_pid_filter():
    assert plugin_metadata.get_plugin_commands({"Off": _DisabledPlugin()}, None) == []  # get_state=False 跳过
    assert plugin_metadata.get_plugin_commands({"FakeP": _FakePlugin()}, "OTHER") == []  # pid 不匹配
