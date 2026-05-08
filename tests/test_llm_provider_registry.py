import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch


def _stub_module(name: str, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        sys.modules[name] = module
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


class _DummyLogger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _DummySystemConfigOper:
    def get(self, _key):
        return {}

    async def async_set(self, _key, _value):
        return None


for _module_name in ("aiofiles", "jwt"):
    _stub_module(_module_name)

_stub_module(
    "app.core.config",
    settings=SimpleNamespace(
        TEMP_PATH="/tmp",
        PROXY_HOST=None,
        LLM_MAX_CONTEXT_TOKENS=64,
    ),
)
_stub_module("app.db.systemconfig_oper", SystemConfigOper=_DummySystemConfigOper)
_stub_module("app.log", logger=_DummyLogger())
_stub_module("app.schemas.types", SystemConfigKey=SimpleNamespace(AIAgentConfig="agent"))

provider_path = Path(__file__).resolve().parents[1] / "app" / "agent" / "llm" / "provider.py"
spec = importlib.util.spec_from_file_location("test_llm_provider_module", provider_path)
provider_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = provider_module
spec.loader.exec_module(provider_module)

LLMProviderError = provider_module.LLMProviderError
LLMProviderManager = provider_module.LLMProviderManager


class LlmProviderRegistryTest(unittest.TestCase):
    def setUp(self):
        LLMProviderManager._instances.clear()

    def tearDown(self):
        LLMProviderManager._instances.clear()

    def test_dynamic_provider_is_exposed_from_models_dev_cache(self):
        manager = LLMProviderManager()
        manager._models_dev_data = {
            "frogbot": {
                "id": "frogbot",
                "name": "FrogBot",
                "npm": "@ai-sdk/openai-compatible",
                "env": ["FROGBOT_API_KEY"],
                "api": "https://app.frogbot.ai/api/v1",
                "models": {},
            }
        }

        provider = manager.get_provider("frogbot")

        self.assertEqual(provider.id, "frogbot")
        self.assertEqual(provider.runtime, "openai_compatible")
        self.assertEqual(provider.default_base_url, "https://app.frogbot.ai/api/v1")
        self.assertFalse(provider.requires_base_url)
        self.assertTrue(provider.base_url_editable)
        self.assertEqual(provider.model_list_strategy, "models_dev_only")

    def test_dynamic_provider_override_normalizes_chat_endpoint_base_url(self):
        manager = LLMProviderManager()
        manager._models_dev_data = {
            "bailing": {
                "id": "bailing",
                "name": "Bailing",
                "npm": "@ai-sdk/openai-compatible",
                "env": ["BAILING_API_TOKEN"],
                "api": "https://api.tbox.cn/api/llm/v1/chat/completions",
                "models": {},
            }
        }

        provider = manager.get_provider("bailing")

        self.assertEqual(provider.default_base_url, "https://api.tbox.cn/api/llm/v1")
        self.assertEqual(provider.api_key_label, "API Token")

    def test_dynamic_provider_skips_alias_only_models_dev_ids(self):
        manager = LLMProviderManager()
        manager._models_dev_data = {
            "moonshotai": {
                "id": "moonshotai",
                "name": "Moonshot AI Intl",
                "npm": "@ai-sdk/openai-compatible",
                "env": ["MOONSHOT_API_KEY"],
                "api": "https://api.moonshot.ai/v1",
                "models": {},
            }
        }

        with self.assertRaises(LLMProviderError):
            manager.get_provider("moonshotai")

    def test_dynamic_provider_skips_incompatible_models_dev_provider(self):
        manager = LLMProviderManager()
        manager._models_dev_data = {
            "azure": {
                "id": "azure",
                "name": "Azure",
                "npm": "@ai-sdk/azure",
                "env": ["AZURE_API_KEY"],
                "models": {},
            }
        }

        with self.assertRaises(LLMProviderError):
            manager.get_provider("azure")

    def test_dynamic_provider_without_known_base_url_requires_manual_input(self):
        manager = LLMProviderManager()
        manager._models_dev_data = {
            "custom-anthropic": {
                "id": "custom-anthropic",
                "name": "Custom Anthropic",
                "npm": "@ai-sdk/anthropic",
                "env": ["CUSTOM_ANTHROPIC_KEY"],
                "models": {},
            }
        }

        provider = manager.get_provider("custom-anthropic")

        self.assertEqual(provider.runtime, "anthropic_compatible")
        self.assertTrue(provider.requires_base_url)
        self.assertTrue(provider.base_url_editable)
        self.assertEqual(provider.model_list_strategy, "anthropic_compatible")

    def test_list_providers_async_loads_models_dev_before_serializing(self):
        manager = LLMProviderManager()
        payload = {
            "frogbot": {
                "id": "frogbot",
                "name": "FrogBot",
                "npm": "@ai-sdk/openai-compatible",
                "env": ["FROGBOT_API_KEY"],
                "api": "https://app.frogbot.ai/api/v1",
                "models": {},
            }
        }

        with patch.object(
            manager,
            "get_models_dev_data",
            AsyncMock(side_effect=lambda force_refresh=False: manager.__dict__.update({"_models_dev_data": payload}) or payload),
        ) as fetch_mock:
            providers = asyncio.run(manager.list_providers_async())

        fetch_mock.assert_awaited_once_with(force_refresh=False)
        self.assertIn("frogbot", {item["id"] for item in providers})

    def test_list_models_uses_dynamic_provider_after_refresh(self):
        manager = LLMProviderManager()
        payload = {
            "frogbot": {
                "id": "frogbot",
                "name": "FrogBot",
                "npm": "@ai-sdk/openai-compatible",
                "env": ["FROGBOT_API_KEY"],
                "api": "https://app.frogbot.ai/api/v1",
                "models": {
                    "frog-1": {
                        "name": "Frog 1",
                        "limit": {"context": 131072},
                    }
                },
            }
        }

        async def _load_models_dev(force_refresh: bool = False):
            manager._models_dev_data = payload
            return payload

        with patch.object(manager, "get_models_dev_data", AsyncMock(side_effect=_load_models_dev)):
            models = asyncio.run(
                manager.list_models(
                    provider_id="frogbot",
                    api_key="sk-test",
                    force_refresh=True,
                )
            )

        self.assertEqual([item["id"] for item in models], ["frog-1"])
        self.assertEqual(models[0]["source"], "models.dev")


if __name__ == "__main__":
    unittest.main()
