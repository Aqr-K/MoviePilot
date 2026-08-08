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


class _AuthPlugin:
    """声明登录入口（SSO）的插件替身。"""

    plugin_name = "假冒 SSO"

    def __init__(self, enabled=True, providers=None, raise_on_call=False):
        self._enabled = enabled
        self._providers = [{"icon": "mdi-login"}] if providers is None else providers
        self._raise = raise_on_call

    def get_state(self):
        return self._enabled

    def get_render_mode(self):
        return "vuetify", None

    def get_auth_providers(self):
        if self._raise:
            raise RuntimeError("插件内部异常")
        return [dict(p) for p in self._providers]


class _PassAuthPlugin:
    """get_auth_providers 仅占位（pass 体）：应被 check_method 判为未实现而跳过。"""

    plugin_name = "占位入口"

    def get_state(self):
        return True

    def get_render_mode(self):
        return "vuetify", None

    def get_auth_providers(self):
        pass


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


# ---- (c) SSO 扩展面防回归：get_plugin_auth_providers 富化与跳过 ----

def test_auth_providers_enriched():
    providers = plugin_metadata.get_plugin_auth_providers({"ghsso": _AuthPlugin(providers=[{"icon": "gh"}])})
    assert len(providers) == 1
    p = providers[0]
    assert p["type"] == "plugin" and p["plugin_id"] == "ghsso"
    assert p["id"] == "plugin:ghsso" and p["name"] == "假冒 SSO" and p["enabled"] is True  # 默认值注入
    assert p["icon"] == "gh"                                                              # 原字段保留


def test_auth_providers_preserve_explicit_fields():
    providers = plugin_metadata.get_plugin_auth_providers(
        {"ghsso": _AuthPlugin(providers=[{"id": "github", "name": "GitHub", "enabled": False}])})
    p = providers[0]
    assert p["id"] == "github" and p["name"] == "GitHub" and p["enabled"] is False  # 显式字段不被默认覆盖
    assert p["type"] == "plugin" and p["plugin_id"] == "ghsso"                       # type/plugin_id 始终强制


def test_auth_providers_skip_disabled_nohook_and_failing():
    assert plugin_metadata.get_plugin_auth_providers({"off": _AuthPlugin(enabled=False)}) == []  # 未启用
    assert plugin_metadata.get_plugin_auth_providers({"nohook": _FakePlugin()}) == []            # 无 get_auth_providers
    assert plugin_metadata.get_plugin_auth_providers({"ph": _PassAuthPlugin()}) == []            # pass 体被 check_method 跳过
    # 抛异常的插件被吞，不影响其它插件
    providers = plugin_metadata.get_plugin_auth_providers(
        {"bad": _AuthPlugin(raise_on_call=True), "good": _AuthPlugin(providers=[{"id": "ok"}])})
    assert [p["id"] for p in providers] == ["ok"]
