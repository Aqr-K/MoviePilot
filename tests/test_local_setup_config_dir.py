from __future__ import annotations

import importlib.util
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "local_setup.py"


def load_local_setup_module():
    module_name = f"moviepilot_local_setup_config_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class LocalSetupConfigDirTests(unittest.TestCase):
    def test_setup_prompts_for_config_dir_when_not_provided(self):
        module = load_local_setup_module()
        default_dir = Path("/tmp/default-moviepilot-config")
        custom_dir = Path("/tmp/custom-moviepilot-config")

        with patch.object(module, "_is_interactive", return_value=True), patch.object(
            module, "resolve_config_dir", return_value=default_dir
        ), patch.object(
            module, "_prompt_path", return_value=str(custom_dir)
        ):
            result = module._resolve_interactive_config_dir("setup", None)

        self.assertEqual(result, custom_dir)

    def test_setup_keeps_default_config_dir_when_user_accepts_default(self):
        module = load_local_setup_module()
        default_dir = Path("/tmp/default-moviepilot-config")

        with patch.object(module, "_is_interactive", return_value=True), patch.object(
            module, "resolve_config_dir", return_value=default_dir
        ), patch.object(
            module, "_prompt_path", return_value=str(default_dir)
        ):
            result = module._resolve_interactive_config_dir("init", None)

        self.assertEqual(result, default_dir)

    def test_non_setup_command_does_not_prompt_for_config_dir(self):
        module = load_local_setup_module()

        with patch.object(module, "_is_interactive", return_value=True), patch.object(
            module, "_prompt_path"
        ) as prompt_mock:
            result = module._resolve_interactive_config_dir("install-deps", None)

        self.assertIsNone(result)
        prompt_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
