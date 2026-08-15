"""插件 UI 聚合面的实例化契约。

侧栏入口、仪表板与登录入口都按实例键归集：同一插件的多个实例各自出条目，条目自带的归属
标识就是该实例注册的接口路由前缀；仪表板按实例键精确定位，裸插件标识只解析到默认实例。
联邦入口是插件源码目录下的一份构建产物，按插件标识去重。

单实例插件的输出必须与不区分实例时逐字段一致，否则全部存量插件的前端入口一次性改名。
单个实例的钩子抛错只丢掉该实例的条目，其余实例照常呈现。
"""
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest
from fastapi import HTTPException

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.runtime.extensions.plugin_instance import instance_key
from app.runtime.extensions.plugin_ui import (
    get_plugin_auth_providers,
    get_plugin_dashboard,
    get_plugin_dashboard_meta,
    get_plugin_remotes,
    get_plugin_sidebar_nav,
)

PLUGIN_ID = "UISurfacePlugin"
ALPHA_KEY = instance_key(PLUGIN_ID, "alpha")
BETA_KEY = instance_key(PLUGIN_ID, "beta")
REMOTE_URL = f"/plugin/file/{PLUGIN_ID.lower()}/dist/assets/remoteEntry.js"


class UIPlugin:
    """声明侧栏入口、仪表板与登录入口的插件替身。"""

    plugin_name = "界面示例插件"

    def __init__(self, instance_id: str = DEFAULT_INSTANCE_ID, enabled: bool = True,
                 failing: Iterable[str] = ()) -> None:
        """
        :param instance_id: 实例标识，用于区分同插件各实例的返回内容
        :param enabled: 实例是否启用
        :param failing: 需要抛错的钩子名集合
        """
        self.instance_id = instance_id
        self.enabled = enabled
        self.failing = set(failing)

    def _guard(self, hook: str) -> None:
        """
        按用例配置让指定钩子抛错

        :param hook: 钩子名
        """
        if hook in self.failing:
            raise RuntimeError(f"{hook} 故障")

    def get_state(self) -> bool:
        self._guard("get_state")
        return self.enabled

    def get_render_mode(self) -> Tuple[str, Optional[str]]:
        self._guard("get_render_mode")
        return "vue", "dist/assets"

    def get_sidebar_nav(self) -> List[Dict[str, Any]]:
        self._guard("get_sidebar_nav")
        return [{"nav_key": "main", "title": "示例入口"}]

    def get_dashboard_meta(self) -> List[Dict[str, str]]:
        self._guard("get_dashboard_meta")
        return [{"key": "board", "name": "示例面板"}]

    def get_dashboard(self, key: str = "", user_agent: str = None) -> Tuple[dict, dict, list]:
        self._guard("get_dashboard")
        return {"cols": 12}, {"title": self.instance_id, "key": key}, []

    def get_auth_providers(self) -> List[Dict[str, Any]]:
        self._guard("get_auth_providers")
        return [{"id": "oidc", "name": "OIDC 登录"}]


def running(*plugins: UIPlugin) -> Dict[str, UIPlugin]:
    """
    按实例键登记若干运行态实例

    :param plugins: 插件替身
    :return: 运行态插件表 {实例键: plugin}
    """
    return {instance_key(PLUGIN_ID, plugin.instance_id): plugin for plugin in plugins}


# --------------------------------------------------------------------------- #
# 侧栏入口
# --------------------------------------------------------------------------- #

def test_every_instance_gets_its_own_sidebar_entry() -> None:
    """同插件双实例声明同名 nav_key 时各自出条目，后聚合的不得顶掉先聚合的。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"), UIPlugin("beta"))

    items = get_plugin_sidebar_nav(plugins)

    assert [item["plugin_id"] for item in items] == [PLUGIN_ID, ALPHA_KEY, BETA_KEY]
    assert {item["nav_key"] for item in items} == {"main"}


def test_sidebar_entries_are_keyed_by_the_instance_route_prefix() -> None:
    """侧栏条目的归属标识是实例键，默认实例退化为裸插件标识。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"))

    items = get_plugin_sidebar_nav(plugins)

    assert {item["plugin_id"] for item in items} == set(plugins)


def test_disabled_instance_has_no_sidebar_entry() -> None:
    """未启用的实例不出侧栏条目，同插件的其余实例照常呈现。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", enabled=False))

    items = get_plugin_sidebar_nav(plugins)

    assert [item["plugin_id"] for item in items] == [PLUGIN_ID]


def test_sidebar_survives_one_instance_state_failure() -> None:
    """单个实例判定启用状态抛错时只丢掉该实例的条目。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", failing=["get_state"]))

    items = get_plugin_sidebar_nav(plugins)

    assert [item["plugin_id"] for item in items] == [PLUGIN_ID]


def test_sidebar_survives_one_instance_hook_failure() -> None:
    """单个实例的侧栏钩子抛错时只丢掉该实例的条目。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", failing=["get_sidebar_nav"]))

    items = get_plugin_sidebar_nav(plugins)

    assert [item["plugin_id"] for item in items] == [PLUGIN_ID]


def test_single_instance_sidebar_entry_is_unchanged() -> None:
    """单实例插件的侧栏条目在既有字段上保持原样。"""
    entry = get_plugin_sidebar_nav(running(UIPlugin()))[0]

    assert {field: entry[field] for field in (
        "plugin_id", "nav_key", "title", "icon", "section", "permission", "order",
    )} == {
        "plugin_id": PLUGIN_ID,
        "nav_key": "main",
        "title": "示例入口",
        "icon": "mdi-puzzle",
        "section": "system",
        "permission": None,
        "order": 0,
    }


# --------------------------------------------------------------------------- #
# 仪表板元信息
# --------------------------------------------------------------------------- #

def test_every_instance_gets_its_own_dashboard_meta() -> None:
    """同插件双实例声明同名仪表板 key 时各自出条目。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"))

    meta = get_plugin_dashboard_meta(plugins)

    assert [item["id"] for item in meta] == [PLUGIN_ID, ALPHA_KEY]
    assert {item["key"] for item in meta} == {"board"}


def test_disabled_instance_has_no_dashboard_meta() -> None:
    """未启用的实例不出仪表板条目。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", enabled=False))

    assert [item["id"] for item in get_plugin_dashboard_meta(plugins)] == [PLUGIN_ID]


def test_dashboard_meta_survives_one_instance_hook_failure() -> None:
    """单个实例的仪表板元信息钩子抛错时只丢掉该实例的条目。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", failing=["get_dashboard_meta"]))

    assert [item["id"] for item in get_plugin_dashboard_meta(plugins)] == [PLUGIN_ID]


def test_single_instance_dashboard_meta_is_unchanged() -> None:
    """单实例插件的仪表板元信息在既有字段上保持原样。"""
    entry = get_plugin_dashboard_meta(running(UIPlugin()))[0]

    assert {field: entry[field] for field in ("id", "name", "key")} == {
        "id": PLUGIN_ID,
        "name": "示例面板",
        "key": "board",
    }


# --------------------------------------------------------------------------- #
# 仪表板数据
# --------------------------------------------------------------------------- #

def test_dashboard_is_resolved_by_instance_key() -> None:
    """按实例键取仪表板时精确命中该实例，不串到同插件的其他实例。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"))

    dashboard = get_plugin_dashboard(plugins, ALPHA_KEY, "board")

    assert dashboard.id == ALPHA_KEY
    assert dashboard.attrs["title"] == "alpha"


def test_bare_plugin_id_resolves_only_the_default_instance() -> None:
    """裸插件标识只解析到默认实例，默认实例未运行时报找不到而不是回落到首个实例。"""
    plugins = running(UIPlugin("alpha"), UIPlugin("beta"))

    with pytest.raises(HTTPException) as exc_info:
        get_plugin_dashboard(plugins, PLUGIN_ID, "board")

    assert exc_info.value.status_code == 404


def test_default_instance_dashboard_is_not_shadowed_by_a_sibling() -> None:
    """分身实例先进入运行态时，裸插件标识仍取默认实例的仪表板。"""
    plugins = running(UIPlugin("alpha"), UIPlugin())

    dashboard = get_plugin_dashboard(plugins, PLUGIN_ID, "board")

    assert dashboard.id == PLUGIN_ID
    assert dashboard.attrs["title"] == DEFAULT_INSTANCE_ID


def test_single_instance_dashboard_is_unchanged() -> None:
    """单实例插件的仪表板逐字段保持原样。"""
    dashboard = get_plugin_dashboard(running(UIPlugin()), PLUGIN_ID, "board")

    assert dashboard.id == PLUGIN_ID
    assert dashboard.name == "界面示例插件"
    assert dashboard.key == "board"
    assert dashboard.render_mode == "vue"
    assert dashboard.cols == {"cols": 12}
    assert dashboard.attrs == {"title": DEFAULT_INSTANCE_ID, "key": "board"}
    assert dashboard.elements == []


# --------------------------------------------------------------------------- #
# 登录认证入口
# --------------------------------------------------------------------------- #

def test_every_instance_gets_its_own_auth_provider() -> None:
    """同插件双实例声明同一个认证入口时各自出条目，且入口标识互不重复。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"))

    providers = get_plugin_auth_providers(plugins)

    assert [provider["plugin_id"] for provider in providers] == [PLUGIN_ID, ALPHA_KEY]
    assert len({provider["id"] for provider in providers}) == 2


def test_disabled_instance_has_no_auth_provider() -> None:
    """未启用的实例不出登录入口。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", enabled=False))

    assert [p["plugin_id"] for p in get_plugin_auth_providers(plugins)] == [PLUGIN_ID]


def test_auth_providers_survive_one_instance_render_mode_failure() -> None:
    """单个实例读取渲染模式抛错时只丢掉该实例的登录入口。"""
    plugins = running(UIPlugin(), UIPlugin("alpha", failing=["get_render_mode"]))

    assert [p["plugin_id"] for p in get_plugin_auth_providers(plugins)] == [PLUGIN_ID]


def test_single_instance_auth_provider_is_unchanged() -> None:
    """单实例插件的登录入口逐字段保持原样。"""
    assert get_plugin_auth_providers(running(UIPlugin())) == [{
        "id": "oidc",
        "name": "OIDC 登录",
        "type": "plugin",
        "plugin_id": PLUGIN_ID,
        "enabled": True,
        "component": "AuthPage",
        "remote": {
            "id": PLUGIN_ID,
            "url": REMOTE_URL,
            "name": "界面示例插件",
        },
    }]


# --------------------------------------------------------------------------- #
# 联邦入口
# --------------------------------------------------------------------------- #

def test_instances_share_one_federation_remote() -> None:
    """同插件的多个实例共用一份构建产物，联邦入口只登记一条。"""
    plugins = running(UIPlugin(), UIPlugin("alpha"))

    assert get_plugin_remotes(plugins) == [{
        "id": PLUGIN_ID,
        "url": REMOTE_URL,
        "name": "界面示例插件",
    }]


def test_remotes_survive_one_instance_render_mode_failure() -> None:
    """单个实例读取渲染模式抛错时不影响其余实例的联邦入口。"""
    plugins = {ALPHA_KEY: UIPlugin("alpha", failing=["get_render_mode"]),
               PLUGIN_ID: UIPlugin()}

    assert [remote["id"] for remote in get_plugin_remotes(plugins)] == [PLUGIN_ID]
