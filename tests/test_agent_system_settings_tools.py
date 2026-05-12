import asyncio
import importlib.util
import json
import sys
import unittest
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]


def _stub_module(name: str, *, package: bool = False, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        if package:
            module.__path__ = []
        sys.modules[name] = module
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _DummyLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


class _DummyMoviePilotTool:
    result_max_chars = None

    def __init__(self, session_id: str, user_id: str, **kwargs):
        self._session_id = session_id
        self._user_id = user_id
        self._require_admin = getattr(self.__class__, "require_admin", False)
        self.name = getattr(self.__class__, "name", self.__class__.__name__)


def _format_tool_result_for_agent(result, **kwargs):
    if isinstance(result, str):
        return result
    return json.dumps(result, ensure_ascii=False, default=str)


class _SystemConfigKey(Enum):
    Downloaders = "Downloaders"
    MediaServers = "MediaServers"
    Notifications = "Notifications"
    NotificationSwitchs = "NotificationSwitchs"
    Directories = "Directories"
    Storages = "Storages"
    IndexerSites = "IndexerSites"
    RssSites = "RssSites"
    CustomReleaseGroups = "CustomReleaseGroups"
    Customization = "Customization"
    CustomIdentifiers = "CustomIdentifiers"
    TransferExcludeWords = "TransferExcludeWords"
    TorrentsPriority = "TorrentsPriority"
    CustomFilterRules = "CustomFilterRules"
    UserFilterRuleGroups = "UserFilterRuleGroups"
    SearchFilterRuleGroups = "SearchFilterRuleGroups"
    SubscribeFilterRuleGroups = "SubscribeFilterRuleGroups"
    SubscribeDefaultParams = "SubscribeDefaultParams"
    BestVersionFilterRuleGroups = "BestVersionFilterRuleGroups"
    SubscribeReport = "SubscribeReport"
    UserCustomCSS = "UserCustomCSS"
    UserInstalledPlugins = "UserInstalledPlugins"
    PluginFolders = "PluginFolders"
    DefaultMovieSubscribeConfig = "DefaultMovieSubscribeConfig"
    DefaultTvSubscribeConfig = "DefaultTvSubscribeConfig"
    UserSiteAuthParams = "UserSiteAuthParams"
    FollowSubscribers = "FollowSubscribers"
    NotificationSendTime = "NotificationSendTime"
    AIAgentConfig = "AIAgentConfig"
    NotificationTemplates = "NotificationTemplates"
    ScrapingSwitchs = "ScrapingSwitchs"
    PluginInstallReport = "PluginInstallReport"
    SetupWizardState = "SetupWizardState"
    UgreenSessionCache = "UgreenSessionCache"


class _EventType(Enum):
    ConfigChanged = "ConfigChanged"


class _DummySettingsModel:
    model_fields = {
        "APP_DOMAIN": object(),
        "TMDB_API_KEY": object(),
    }


class _DummySettings:
    APP_DOMAIN = "https://old.example.com"
    TMDB_API_KEY = "demo-token"

    def update_setting(self, key, value):
        setattr(self, key, value)
        return True, ""


class _DummySystemConfigOper:
    def get(self, key):
        return None

    async def async_set(self, key, value):
        return True


class _DummyEventManager:
    async def async_send_event(self, *args, **kwargs):
        return None


@dataclass
class _ConfigChangeEventData:
    key: object
    value: object = None
    change_type: str = "update"


class _StubToolFactory:
    @staticmethod
    def create_tools(*args, **kwargs):
        return []


for _package_name in (
    "app",
    "app.agent",
    "app.agent.tools",
    "app.agent.tools.impl",
    "app.core",
    "app.db",
    "app.schemas",
):
    _stub_module(_package_name, package=True)

_stub_module(
    "app.agent.tools.base",
    MoviePilotTool=_DummyMoviePilotTool,
    format_tool_result_for_agent=_format_tool_result_for_agent,
)
_stub_module(
    "app.core.config",
    Settings=_DummySettingsModel,
    settings=_DummySettings(),
)
_stub_module("app.db.systemconfig_oper", SystemConfigOper=_DummySystemConfigOper)
_stub_module("app.log", logger=_DummyLogger())
_stub_module("app.core.event", eventmanager=_DummyEventManager())
_stub_module("app.schemas.event", ConfigChangeEventData=_ConfigChangeEventData)
_stub_module(
    "app.schemas.types",
    SystemConfigKey=_SystemConfigKey,
    EventType=_EventType,
)
_stub_module("app.agent.tools.factory", MoviePilotToolFactory=_StubToolFactory)

_load_module(
    "app.agent.tools.impl._system_setting_utils",
    "app/agent/tools/impl/_system_setting_utils.py",
)
query_module = _load_module(
    "app.agent.tools.impl.query_system_settings",
    "app/agent/tools/impl/query_system_settings.py",
)
update_module = _load_module(
    "app.agent.tools.impl.update_system_settings",
    "app/agent/tools/impl/update_system_settings.py",
)
manager_module = _load_module(
    "app.agent.tools.manager",
    "app/agent/tools/manager.py",
)

QuerySystemSettingsTool = query_module.QuerySystemSettingsTool
UpdateSystemSettingsTool = update_module.UpdateSystemSettingsTool
MoviePilotToolsManager = manager_module.MoviePilotToolsManager


class TestAgentSystemSettingsTools(unittest.TestCase):
    def test_query_system_settings_returns_exact_systemconfig_value(self):
        tool = QuerySystemSettingsTool(session_id="session-1", user_id="10001")
        config_oper = MagicMock()
        config_oper.get.return_value = [{"name": "qb", "enabled": True}]

        with patch.object(query_module, "SystemConfigOper", return_value=config_oper):
            result = asyncio.run(tool.run(setting_key="Downloaders"))

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["matched_count"], 1)
        self.assertEqual(payload["settings"][0]["setting_key"], "Downloaders")
        self.assertEqual(payload["settings"][0]["value"][0]["name"], "qb")

    def test_query_system_settings_group_defaults_to_summary_for_multiple_items(self):
        tool = QuerySystemSettingsTool(session_id="session-1", user_id="10001")
        config_oper = MagicMock()
        config_oper.get.return_value = []

        with patch.object(query_module, "SystemConfigOper", return_value=config_oper):
            result = asyncio.run(tool.run(group="systemconfig"))

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertFalse(payload["include_values"])
        self.assertGreater(payload["matched_count"], 1)

    def test_update_system_settings_merges_dict_and_emits_event(self):
        tool = UpdateSystemSettingsTool(session_id="session-1", user_id="10001")
        config_oper = MagicMock()
        config_oper.get.side_effect = [
            {"chatgpt": {"enabled": True}},
            {"chatgpt": {"enabled": False}, "gemini": {"enabled": True}},
        ]
        config_oper.async_set = AsyncMock(return_value=True)

        with patch.object(
            update_module, "SystemConfigOper", return_value=config_oper
        ), patch.object(
            update_module.eventmanager,
            "async_send_event",
            new=AsyncMock(),
        ) as send_event:
            result = asyncio.run(
                tool.run(
                    setting_key="AIAgentConfig",
                    operation="merge_dict",
                    value={"chatgpt": {"enabled": False}, "gemini": {"enabled": True}},
                )
            )

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertTrue(payload["changed"])
        config_oper.async_set.assert_awaited_once_with(
            "AIAgentConfig",
            {"chatgpt": {"enabled": False}, "gemini": {"enabled": True}},
        )
        send_event.assert_awaited_once()

    def test_update_system_settings_upserts_named_list_item(self):
        tool = UpdateSystemSettingsTool(session_id="session-1", user_id="10001")
        config_oper = MagicMock()
        config_oper.get.side_effect = [
            [{"name": "qb", "enabled": False}],
            [{"name": "qb", "enabled": True}],
        ]
        config_oper.async_set = AsyncMock(return_value=True)

        with patch.object(
            update_module, "SystemConfigOper", return_value=config_oper
        ), patch.object(
            update_module.eventmanager,
            "async_send_event",
            new=AsyncMock(),
        ):
            result = asyncio.run(
                tool.run(
                    setting_key="downloaders",
                    operation="upsert_list_item",
                    value={"name": "qb", "enabled": True},
                )
            )

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["saved_value"], [{"name": "qb", "enabled": True}])

    def test_update_system_settings_updates_basic_settings(self):
        tool = UpdateSystemSettingsTool(session_id="session-1", user_id="10001")

        with patch.object(
            update_module.settings,
            "update_setting",
            return_value=(True, ""),
        ) as update_setting, patch.object(
            UpdateSystemSettingsTool,
            "_load_setting_value",
            side_effect=["https://old.example.com", "https://new.example.com"],
        ), patch.object(
            update_module.eventmanager,
            "async_send_event",
            new=AsyncMock(),
        ) as send_event:
            result = asyncio.run(
                tool.run(setting_key="APP_DOMAIN", value="https://new.example.com")
            )

        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertTrue(payload["changed"])
        update_setting.assert_called_once_with("APP_DOMAIN", "https://new.example.com")
        send_event.assert_awaited_once()

    def test_tool_manager_blocks_admin_tools_for_non_admin_context(self):
        tool = QuerySystemSettingsTool(session_id="session-1", user_id="10001")

        with patch.object(
            manager_module.MoviePilotToolFactory,
            "create_tools",
            return_value=[tool],
        ):
            manager = MoviePilotToolsManager(is_admin=False)
            result = asyncio.run(
                manager.call_tool(
                    "query_system_settings",
                    {"setting_key": "Downloaders"},
                )
            )

        payload = json.loads(result)
        self.assertIn("error", payload)
        self.assertIn("系统管理员", payload["error"])


if __name__ == "__main__":
    unittest.main()
