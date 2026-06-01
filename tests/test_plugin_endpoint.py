import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, MagicMock, patch


class PluginEndpointTest(TestCase):

    def test_plugin_history_merges_remote_metadata(self):
        """
        已安装插件点击更新说明时，接口会按需合并远端仓库中的更新记录。
        """
        try:
            from app import schemas
            from app.api.endpoints.plugin import plugin_history
        except ModuleNotFoundError as exc:
            self.skipTest(f"missing dependency: {exc}")

        installed_plugin = schemas.Plugin(
            id="DemoPlugin",
            plugin_name="Demo Plugin",
            plugin_version="1.0.0",
            installed=True,
            history={},
        )
        market_plugin = schemas.Plugin(
            id="DemoPlugin",
            repo_url="https://github.com/demo/plugins",
            history={"v1.1.0": "- 新增更新说明"},
            system_version=">=2.0.0",
            system_version_compatible=True,
            has_update=True,
        )
        plugin_manager = MagicMock()
        plugin_manager.get_local_plugins.return_value = [installed_plugin]
        plugin_manager.get_local_repo_plugins.return_value = []
        plugin_manager.async_get_online_plugins = AsyncMock(return_value=[market_plugin])

        with patch("app.api.endpoints.plugin.PluginManager", return_value=plugin_manager):
            result = asyncio.run(plugin_history("DemoPlugin", None, True))

        self.assertEqual("https://github.com/demo/plugins", result.repo_url)
        self.assertEqual({"v1.1.0": "- 新增更新说明"}, result.history)
        self.assertEqual(">=2.0.0", result.system_version)
        self.assertTrue(result.has_update)

    def test_plugin_history_returns_installed_plugin_when_remote_missing(self):
        """
        远端仓库不可用时，接口仍返回本地已安装插件信息，前端可继续展示兜底状态。
        """
        try:
            from app import schemas
            from app.api.endpoints.plugin import plugin_history
        except ModuleNotFoundError as exc:
            self.skipTest(f"missing dependency: {exc}")

        installed_plugin = schemas.Plugin(
            id="DemoPlugin",
            plugin_name="Demo Plugin",
            plugin_version="1.0.0",
            installed=True,
        )
        plugin_manager = MagicMock()
        plugin_manager.get_local_plugins.return_value = [installed_plugin]
        plugin_manager.get_local_repo_plugins.return_value = []
        plugin_manager.async_get_online_plugins = AsyncMock(return_value=[])

        with patch("app.api.endpoints.plugin.PluginManager", return_value=plugin_manager):
            result = asyncio.run(plugin_history("DemoPlugin", None, True))

        self.assertEqual("DemoPlugin", result.id)
        self.assertEqual({}, result.history)
