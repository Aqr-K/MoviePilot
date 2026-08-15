import asyncio
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from fastapi import HTTPException

from app.agent.tools.impl import _plugin_tool_utils
from app.api.endpoints import plugin as plugin_endpoint
from app.runtime.config import settings
from app.runtime.deprecation import policy as policy_module
from app.runtime.deprecation.notices import DeprecationStage
from app.runtime.deprecation.policy import DeprecatedFeatureError

CLONE_KEY = "plugin.clone_by_source_copy"
PLUGIN_ID = "DemoPlugin"


def _make_plugin_dir(root):
    """在临时根目录下造一个插件源码目录。"""
    plugin_dir = root / "app" / "plugins" / PLUGIN_ID.lower()
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("", encoding="utf-8")
    return plugin_dir


def _make_manager():
    """构造记录调用顺序的插件管理器替身。"""
    manager = MagicMock()
    manager.delete_plugin_config.return_value = True
    manager.delete_plugin_data.return_value = True
    return manager


def test_clone_notice_is_registered_as_removed():
    """复制源码目录式分身的废弃登记已推进到彻底移除阶段。"""
    notice = policy_module.get_notice(CLONE_KEY)

    assert notice.stage is DeprecationStage.REMOVED


def test_clone_guard_raises_at_removed_stage(monkeypatch):
    """处于彻底移除阶段时，guard 触达即抛错且无法被开关恢复。"""
    monkeypatch.setattr(policy_module, "_enabled_keys", lambda: frozenset({CLONE_KEY}))

    assert policy_module.is_active(CLONE_KEY) is False
    with pytest.raises(DeprecatedFeatureError) as excinfo:
        policy_module.guard(CLONE_KEY, context=PLUGIN_ID)
    assert PLUGIN_ID in str(excinfo.value)


def test_clone_route_is_still_registered():
    """旧前端与旧脚本仍能命中路由，从而拿到明确报错而不是 404。"""
    routes = {
        (route.path, method)
        for route in plugin_endpoint.router.routes
        for method in route.methods
    }

    assert ("/clone/{plugin_id}", "POST") in routes


def test_clone_endpoint_returns_gone_with_migration_guidance():
    """分身接口一律以 410 拒绝，并带上废弃登记中的迁移指引。"""
    with pytest.raises(HTTPException) as excinfo:
        plugin_endpoint.clone_plugin(PLUGIN_ID, None)

    exc = excinfo.value
    assert exc.status_code == 410
    assert PLUGIN_ID in exc.detail
    assert "instance_id" in exc.detail
    assert "已彻底移除" in exc.detail


def _run_api_uninstall(root):
    """走 API 层卸载普通插件，返回插件管理器替身。"""
    manager = _make_manager()
    config_oper = MagicMock()
    config_oper.get.return_value = [PLUGIN_ID]

    with (
        patch.object(type(settings), "ROOT_PATH", new_callable=PropertyMock) as root_path,
        patch("app.api.endpoints.plugin.PluginManager", return_value=manager),
        patch("app.api.endpoints.plugin.SystemConfigOper", return_value=config_oper),
        patch("app.api.endpoints.plugin.remove_plugin_api"),
        patch("app.api.endpoints.plugin.Scheduler"),
        patch("app.api.endpoints.plugin._remove_plugin_from_folders"),
        patch("shutil.rmtree") as rmtree,
    ):
        root_path.return_value = root
        result = plugin_endpoint.uninstall_plugin(PLUGIN_ID, None)

    assert result.success is True
    assert rmtree.call_count == 0
    return manager


def _run_agent_uninstall(root):
    """走 Agent 工具层卸载普通插件，返回插件管理器替身。"""
    manager = _make_manager()
    config_oper = MagicMock()
    config_oper.get.return_value = [PLUGIN_ID]
    config_oper.async_set = AsyncMock(return_value=True)

    with (
        patch.object(type(settings), "ROOT_PATH", new_callable=PropertyMock) as root_path,
        patch("app.agent.tools.impl._plugin_tool_utils.PluginManager", return_value=manager),
        patch("app.agent.tools.impl._plugin_tool_utils.SystemConfigOper", return_value=config_oper),
        patch("app.api.endpoints.plugin.remove_plugin_api"),
        patch("app.api.endpoints.plugin._remove_plugin_from_folders"),
        patch("app.scheduler.Scheduler"),
        patch("shutil.rmtree") as rmtree,
    ):
        root_path.return_value = root
        result = asyncio.run(_plugin_tool_utils.uninstall_plugin_runtime(PLUGIN_ID))

    assert result == {"config_retained": True, "data_retained": True}
    assert rmtree.call_count == 0
    return manager


def test_api_uninstall_retains_config_and_data_and_keeps_plugin_dir(tmp_path):
    """API 卸载插件保留配置与数据，插件源码目录也保持原样，重新安装即可复用。"""
    plugin_dir = _make_plugin_dir(tmp_path)

    manager = _run_api_uninstall(tmp_path)

    manager.delete_plugin_config.assert_not_called()
    manager.delete_plugin_data.assert_not_called()
    manager.remove_plugin.assert_called_once_with(PLUGIN_ID)
    assert plugin_dir.exists()
    assert (plugin_dir / "__init__.py").exists()


def test_agent_uninstall_retains_config_and_data_and_keeps_plugin_dir(tmp_path):
    """Agent 工具卸载插件保留配置与数据，插件源码目录也保持原样。"""
    plugin_dir = _make_plugin_dir(tmp_path)

    manager = _run_agent_uninstall(tmp_path)

    manager.delete_plugin_config.assert_not_called()
    manager.delete_plugin_data.assert_not_called()
    manager.remove_plugin.assert_called_once_with(PLUGIN_ID)
    assert plugin_dir.exists()
    assert (plugin_dir / "__init__.py").exists()


def test_both_uninstall_paths_touch_plugin_manager_identically(tmp_path):
    """API 与 Agent 两条卸载路径对插件管理器的调用序列必须一致。"""
    api_root = tmp_path / "api"
    agent_root = tmp_path / "agent"
    _make_plugin_dir(api_root)
    _make_plugin_dir(agent_root)

    api_manager = _run_api_uninstall(api_root)
    agent_manager = _run_agent_uninstall(agent_root)

    expected = [
        ("remove_plugin", (PLUGIN_ID,), {}),
    ]
    assert list(api_manager.method_calls) == expected
    assert list(agent_manager.method_calls) == expected
