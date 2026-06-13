---
name: create-moviepilot-plugin
version: 1
description: >-
  Use this skill when the user asks to create, modify, debug, validate, or
  scaffold a MoviePilot local plugin. Covers MoviePilot V2 plugin development,
  _PluginBase implementations, package.v2.json/package.json market metadata,
  plugins.v2/plugins source layout, PLUGIN_LOCAL_REPO_PATHS local plugin
  sources, plugin APIs, forms, pages, dashboards, commands, services, workflow
  actions, agent tools, and local install/reload flows. Also use for Chinese
  requests mentioning 编写插件、本地插件源、插件开发、V2插件、插件市场、本地安装插件、插件热加载.
allowed-tools: list_directory read_file write_file edit_file execute_command query_system_settings update_system_settings query_market_plugins install_plugin reload_plugin query_installed_plugins
---

# Create MoviePilot Plugin

Use this skill to build or revise MoviePilot plugins that can be developed from
a local plugin source and installed into the running MoviePilot instance.

## Ground Truth

- Host plugin contract: `app/plugins/__init__.py`, especially `_PluginBase`.
- Host plugin discovery, local source sync, install, reload: `app/core/plugin.py`
  and `app/helper/plugin.py`.
- Local development note: `docs/development-setup.md`.
- Plugin repository conventions: `MoviePilot-Plugins` uses `plugins.v2/` with
  `package.v2.json` for V2 plugins; legacy or cross-generation entries may use
  `plugins/` with `package.json`.

## Pre-Flight

1. Understand the user request: plugin purpose, trigger mode, configuration,
   output UI, whether it needs a scheduler, API, command, workflow action, or
   agent tool.
2. Inspect existing plugins before creating a new one:
   - Local runtime examples: `app/plugins/<plugin>/__init__.py`
   - Market/local source candidates: use `query_market_plugins` when the
     running instance is available.
3. Determine the target source path:
   - Query `PLUGIN_LOCAL_REPO_PATHS` with `query_system_settings` when possible.
   - If exactly one local plugin repository is configured, prefer that path.
   - If several are configured, choose the one the user named; otherwise ask
     which repository to use.
   - If none is configured, set it before writing plugin code:
     `update_system_settings(setting_key="PLUGIN_LOCAL_REPO_PATHS", value="local-plugins", operation="replace")`.
     `local-plugins` is resolved relative to the MoviePilot root by the local
     plugin source loader. Create that source directory and write the plugin
     under it; do not write new plugin source directly into `app/plugins/`
     unless the user explicitly asks for a runtime-only experiment.
4. Choose the plugin ID:
   - Class name is the plugin ID, for example `MyNotifier`.
   - Directory name is the class name lowercased, for example `mynotifier`.
   - Avoid collisions with installed or market plugins unless the user is
     explicitly modifying that plugin.

## Local Source Layout

Default to V2 layout for new local plugins:

```text
<local-plugin-repo>/
├── package.v2.json
└── plugins.v2/
    └── <plugin_id_lower>/
        ├── __init__.py
        ├── requirements.txt        # only when extra runtime dependencies are necessary
        └── ...                     # helper modules, schemas, static assets
```

Only use the legacy layout when the user explicitly needs it:

```text
<local-plugin-repo>/
├── package.json
└── plugins/
    └── <plugin_id_lower>/
        └── __init__.py
```

For legacy `package.json` entries that should work on V2, include `"v2": true`.
For V2-first work, prefer `package.v2.json` and `plugins.v2/`.

## Package Metadata

Add or update the package entry for the plugin ID. Keep the package version and
the class `plugin_version` synchronized.

```json
{
  "MyNotifier": {
    "name": "通知示例",
    "description": "根据用户配置发送示例通知。",
    "labels": "消息通知",
    "version": "1.0.0",
    "icon": "mynotifier.png",
    "author": "local",
    "level": 1,
    "system_version": ">=2.12.0",
    "history": {
      "v1.0.0": "初始版本"
    }
  }
}
```

Rules:

- The package object key must match the plugin class name.
- `version` must match `plugin_version`.
- `name`, `description`, `icon`, `author`, and `level` should match the plugin
  class attributes when those attributes exist.
- `history` should record user-readable changes for each published version.
- Use `system_version` when the plugin depends on a host capability introduced
  in a specific MoviePilot version.
- Use `"release": true` only when the plugin is intentionally distributed by a
  GitHub Release archive.
- Do not add dependencies unless they are actually required. If
  `requirements.txt` changes, the user must reinstall the plugin; hot reload is
  not enough to install dependencies.

## Implementation Skeleton

Implement all abstract methods from `_PluginBase`. All new public classes,
public methods, and public functions need Chinese docstrings.

```python
from typing import Any, Dict, List, Optional, Tuple

from app.plugins import _PluginBase


class MyNotifier(_PluginBase):
    """通知示例插件。"""

    plugin_name = "通知示例"
    plugin_desc = "根据用户配置发送示例通知。"
    plugin_icon = "mynotifier.png"
    plugin_version = "1.0.0"
    plugin_label = "消息通知"
    plugin_author = "local"
    plugin_config_prefix = "mynotifier_"
    plugin_order = 100
    auth_level = 1

    _enabled = False
    _message = ""

    def init_plugin(self, config: dict = None) -> None:
        """根据插件配置初始化运行状态。"""
        self.stop_service()
        self._enabled = False
        self._message = ""
        if not config:
            return
        self._enabled = bool(config.get("enabled"))
        self._message = str(config.get("message") or "")

    def get_state(self) -> bool:
        """获取插件启用状态。"""
        return self._enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """返回插件远程命令列表。"""
        return []

    def get_api(self) -> List[Dict[str, Any]]:
        """返回插件 API 列表。"""
        return []

    def get_form(self) -> Tuple[Optional[List[dict]], Dict[str, Any]]:
        """返回插件配置表单与默认配置。"""
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VSwitch",
                        "props": {
                            "model": "enabled",
                            "label": "启用插件"
                        }
                    },
                    {
                        "component": "VTextField",
                        "props": {
                            "model": "message",
                            "label": "通知内容"
                        }
                    }
                ]
            }
        ], {
            "enabled": False,
            "message": ""
        }

    def get_page(self) -> Optional[List[dict]]:
        """返回插件详情页面。"""
        if not self._enabled:
            return None
        return [
            {
                "component": "VAlert",
                "props": {
                    "type": "info",
                    "text": self._message or "插件已启用"
                }
            }
        ]

    def stop_service(self) -> None:
        """停止插件后台服务并释放资源。"""
        return None
```

## Extension Points

Use only the extension points the requested plugin actually needs:

- Configuration: `get_form()` returns Vuetify form schema and default data;
  `init_plugin()` reads config; `update_config()` persists internal changes.
- Data: use `save_data()`, `get_data()`, `del_data()`, and `get_data_path()`.
- Notification: use `post_message()` instead of directly calling message
  modules.
- APIs: return route definitions from `get_api()`; default auth is `apikey`
  when `auth` is omitted.
- Commands: return slash-command definitions from `get_command()` and dispatch
  through MoviePilot events.
- Services: return scheduler services from `get_service()` and always clean
  them up in `stop_service()`.
- Dashboards: use `get_dashboard_meta()` and `get_dashboard()` for homepage
  widgets.
- Workflow actions: use `get_actions()`; action functions receive
  `ActionContent` first and return `(success, action_content)`.
- Agent tools: use `get_agent_tools()`; each tool class must inherit
  `app.agent.tools.base.MoviePilotTool`.
- Custom Vue UI: implement `get_render_mode()` only when Vuetify schema cannot
  satisfy the request. Return `("vue", "<compiled-assets-path>")` and include
  built frontend assets in the plugin directory.

## Local Install And Reload

1. After writing files in a configured local plugin repository, call
   `query_market_plugins(query="<PluginID>", force_refresh=True)` to confirm the
   local source is visible.
2. Install or reinstall with `install_plugin(plugin_id="<PluginID>", force=True)`.
   The install flow copies the source into `app/plugins/<plugin_id_lower>/`.
3. If `PLUGIN_AUTO_RELOAD` or development mode is enabled, Python source changes
   in an installed local plugin can auto-sync and reload. If it is not enabled,
   call `reload_plugin(plugin_id="<PluginID>")` after editing runtime files.
4. When `requirements.txt` changes, reinstall with `force=True`; reloading alone
   does not install new dependencies.

## Validation

- Re-read the changed files and confirm class name, directory name, package ID,
  and package version are consistent.
- Confirm every public class, public method, and public function has a Chinese
  docstring.
- Keep external HTTP calls behind MoviePilot utilities and avoid real network
  calls in tests.
- If the plugin has non-trivial logic, add or update pytest-native tests. Plugin
  repositories can use `app.testing.bootstrap.prepare_v2_backend()` to prepare a
  temporary MoviePilot backend and inject `<repo>/plugins.v2` into `sys.path`.
- Run the narrowest allowed validation for the touched area. In this repository,
  follow `docs/rules/03-commands.md`; for plugin-only repositories, follow their
  own documented validation commands.

## Final Report

Report:

- Plugin ID, source path, and runtime path if installed.
- Package file changed (`package.v2.json` or `package.json`).
- Whether the plugin was installed or reloaded.
- Validation commands run, or why validation was not run.
