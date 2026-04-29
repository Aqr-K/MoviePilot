import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.agent.tools.impl.query_plugin_config import QueryPluginConfigTool
from app.agent.tools.impl.query_plugin_data import QueryPluginDataTool
from app.agent.tools.impl.reload_plugin import ReloadPluginTool
from app.agent.tools.impl.update_plugin_config import UpdatePluginConfigTool


class TestAgentPluginTools(unittest.TestCase):
    @staticmethod
    def _plugin_snapshot(state: bool = True) -> dict:
        return {
            "plugin_id": "DemoPlugin",
            "plugin_name": "Demo Plugin",
            "plugin_version": "1.0.0",
            "state": state,
        }

    def test_query_plugin_config_returns_saved_config_and_default_model(self):
        tool = QueryPluginConfigTool(session_id="session-1", user_id="10001")
        plugin_manager = MagicMock()
        plugin_manager.get_plugin_config.return_value = {"enabled": True}
        plugin_instance = MagicMock()
        plugin_instance.get_form.return_value = (None, {"enabled": False, "interval": 10})
        plugin_manager.running_plugins = {"DemoPlugin": plugin_instance}

        with patch(
            "app.agent.tools.impl.query_plugin_config.get_plugin_snapshot",
            return_value=self._plugin_snapshot(),
        ), patch(
            "app.agent.tools.impl.query_plugin_config.PluginManager",
            return_value=plugin_manager,
        ):
            result = asyncio.run(tool.run(plugin_id="DemoPlugin"))

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["config"], {"enabled": True})
        self.assertEqual(payload["default_model"], {"enabled": False, "interval": 10})

    def test_update_plugin_config_merges_and_removes_keys_without_reloading(self):
        tool = UpdatePluginConfigTool(session_id="session-1", user_id="10001")
        plugin_manager = MagicMock()
        plugin_manager.get_plugin_config.return_value = {
            "enabled": False,
            "interval": 30,
            "token": "legacy-token",
        }
        plugin_manager.async_save_plugin_config = AsyncMock(return_value=True)

        with patch(
            "app.agent.tools.impl.update_plugin_config.get_plugin_snapshot",
            return_value=self._plugin_snapshot(),
        ), patch(
            "app.agent.tools.impl.update_plugin_config.PluginManager",
            return_value=plugin_manager,
        ):
            result = asyncio.run(
                tool.run(
                    plugin_id="DemoPlugin",
                    updates={"enabled": True},
                    remove_keys=["token"],
                )
            )

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertTrue(payload["config_requires_reload"])
        self.assertEqual(payload["saved_config"], {"enabled": True, "interval": 30})
        plugin_manager.async_save_plugin_config.assert_awaited_once_with(
            "DemoPlugin",
            {"enabled": True, "interval": 30},
        )

    def test_reload_plugin_triggers_runtime_refresh(self):
        tool = ReloadPluginTool(session_id="session-1", user_id="10001")

        with patch(
            "app.agent.tools.impl.reload_plugin.get_plugin_snapshot",
            side_effect=[self._plugin_snapshot(), self._plugin_snapshot(state=False)],
        ), patch(
            "app.agent.tools.impl.reload_plugin.reload_plugin_runtime"
        ) as reload_plugin_runtime:
            result = asyncio.run(tool.run(plugin_id="DemoPlugin"))

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertFalse(payload["state"])
        reload_plugin_runtime.assert_called_once_with("DemoPlugin")

    def test_query_plugin_data_truncates_large_payload(self):
        tool = QueryPluginDataTool(session_id="session-1", user_id="10001")
        plugin_data_oper = MagicMock()
        plugin_data_oper.async_get_data_all = AsyncMock(return_value=[
            SimpleNamespace(key="payload", value={"text": "x" * 5000})
        ])

        with patch(
            "app.agent.tools.impl.query_plugin_data.get_plugin_snapshot",
            return_value=self._plugin_snapshot(),
        ), patch(
            "app.agent.tools.impl.query_plugin_data.PluginDataOper",
            return_value=plugin_data_oper,
        ):
            result = asyncio.run(tool.run(plugin_id="DemoPlugin", max_chars=200))

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertTrue(payload["truncated"])
        self.assertIn("data_preview", payload)
        self.assertNotIn("data", payload)
        self.assertIn("已截断", payload["data_preview"])


if __name__ == "__main__":
    unittest.main()
