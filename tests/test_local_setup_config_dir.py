from __future__ import annotations

import importlib.util
import tempfile
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

    def test_install_deps_installs_browser_runtime(self):
        module = load_local_setup_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            venv_dir = (Path(temp_dir) / "venv").resolve()
            venv_python = venv_dir / "bin" / "python"
            venv_pip = venv_dir / "bin" / "pip"

            with patch.object(module, "ensure_supported_python"), \
                    patch.object(module, "ensure_rust_accel_ready") as rust_ready, \
                    patch.object(module, "install_rust_accel") as install_rust, \
                    patch.object(
                        module,
                        "configure_venv_pip_compat",
                        return_value=venv_pip,
                    ), \
                    patch.object(module, "run") as run_mock, \
                    patch.object(module, "install_browser_runtime") as install_browser:
                result = module.install_deps(
                    python_bin="python3",
                    venv_dir=venv_dir,
                    recreate=False,
                )

        self.assertEqual(result, venv_python)
        run_mock.assert_any_call(["python3", "-m", "venv", str(venv_dir)])
        run_mock.assert_any_call(
            [str(venv_pip), "install", "-r", str(module.ROOT / "requirements.txt")]
        )
        rust_ready.assert_called_once_with()
        install_rust.assert_called_once_with(venv_python)
        install_browser.assert_called_once_with(venv_python)

    def test_install_rust_accel_runs_maturin_develop(self):
        """
        验证本地 CLI 安装会通过 maturin 将 Rust 扩展安装进虚拟环境。
        """
        module = load_local_setup_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "Cargo.toml"
            manifest.write_text("[package]\nname = \"moviepilot_rust\"\n")
            venv_python = Path(temp_dir) / "venv" / "bin" / "python"

            with patch.object(module, "RUST_ACCEL_MANIFEST", manifest), \
                    patch.object(module, "_rust_accel_should_skip", return_value=False), \
                    patch.object(module, "ensure_rust_accel_ready"), \
                    patch.object(module, "_cargo_env_path", return_value="/cargo/bin:/bin"), \
                    patch.object(module, "run") as run_mock:
                module.install_rust_accel(venv_python)

        run_mock.assert_called_once()
        command = run_mock.call_args.args[0]
        self.assertEqual(
            command,
            [
                str(venv_python),
                "-m",
                "maturin",
                "develop",
                "--release",
                "--manifest-path",
                str(manifest),
            ],
        )
        self.assertEqual(run_mock.call_args.kwargs["env"]["PATH"], "/cargo/bin:/bin")

    def test_ensure_rust_accel_ready_requires_cargo(self):
        """
        验证 Rust 扩展源码存在时，CLI 安装会检查 cargo 是否可用。
        """
        module = load_local_setup_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "Cargo.toml"
            manifest.write_text("[package]\nname = \"moviepilot_rust\"\n")

            with patch.object(module, "RUST_ACCEL_MANIFEST", manifest), \
                    patch.object(module, "_rust_accel_should_skip", return_value=False), \
                    patch.object(module, "_find_cargo", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "cargo"):
                    module.ensure_rust_accel_ready()

    def test_ensure_rust_accel_ready_allows_skip(self):
        """
        验证显式跳过 Rust 扩展时，不再要求本机存在 cargo。
        """
        module = load_local_setup_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "Cargo.toml"
            manifest.write_text("[package]\nname = \"moviepilot_rust\"\n")

            with patch.object(module, "RUST_ACCEL_MANIFEST", manifest), \
                    patch.object(module, "_rust_accel_should_skip", return_value=True), \
                    patch.object(module, "_find_cargo", return_value=None):
                module.ensure_rust_accel_ready()


if __name__ == "__main__":
    unittest.main()
